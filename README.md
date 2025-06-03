# EC2 Instancia NAT con CDK .NET

- [EC2 Instancia NAT con CDK .NET](#ec2-instancia-nat-con-cdk-net)
  - [Introducción](#introducción)
  - [Recursos Requeridos](#recursos-requeridos)
    - [VPC y Subnets Públicas](#vpc-y-subnets-públicas)
  - [Recursos Creados](#recursos-creados)
    - [Grupo de Seguridad](#grupo-de-seguridad)
    - [Key Pair](#key-pair)
    - [Instancia EC2](#instancia-ec2)
    - [Ruta en Tabla de Enrutamiento](#ruta-en-tabla-de-enrutamiento)
  - [Despliegue](#despliegue)
    - [Variables y Secretos de Entorno](#variables-y-secretos-de-entorno)

## Introducción

* El siguiente repositorio es para crear una instancia NAT usando el servicio [AWS EC2](https://aws.amazon.com/es/ec2/). 
* La instancia se desplegará en una subnet pública y otorgará servicio NAT para los recursos desplegados en las subnets privadas con acceso a internet.
* La infraestructura se despliega mediante IaC, usando [AWS CDK en .NET 8.0](https://docs.aws.amazon.com/cdk/api/v2/dotnet/api/).
* El despliegue CI/CD se lleva a cabo mediante  [GitHub Actions](https://github.com/features/actions).

## Recursos Requeridos

### VPC y Subnets Públicas

Es necesario contar con la información de la VPC y subnets públicas a las cuales pertenecerá la instancia EC2.

<ins>Código para obtener VPC existente:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

IVpc vpc = Vpc.FromLookup(this, ..., new VpcLookupOptions {
    VpcId = ...
});
```

<ins>Código para obtener Subnets existentes:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

ISubnet subnet1 = Subnet.FromSubnetAttributes(this, ..., new SubnetAttributes { 
    SubnetId = ...,
    AvailabilityZone = ...,
});
ISubnet subnet2 = Subnet.FromSubnetAttributes(this, ..., new SubnetAttributes { 
    SubnetId = ...,
    AvailabilityZone = ...,
});
```

## Recursos Creados

### Grupo de Seguridad

Se crea el grupo de seguridad asociado a la instancia EC2. Este grupo de seguridad tendrá las reglas de ingreso y egreso para HTTP y HTTPS que provengan desde los CIDR de las subnets privadas que contendrán acceso a internet y que tengan como objetivo cualquier destino, además tendrá una regla de ingreso para SSH para habilitar acceso a la instancia desde internet.

<ins>Código para crear Grupo de Seguridad:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

// Se crea security group...
ISecurityGroup securityGroup = new SecurityGroup(this, ..., new SecurityGroupProps {
    Vpc = vpc,
    SecurityGroupName = ...,
    Description = ...,
    AllowAllOutbound = false,
});
// Se crean reglas de ingress para HTTP desde redes privadas con internet...
securityGroup.AddIngressRule(Peer.Ipv4(...), Port.HTTP, ...);
securityGroup.AddIngressRule(Peer.Ipv4(...), Port.HTTP, ...);
// Se crean reglas de ingress para HTTPS desde redes privadas con internet...
securityGroup.AddIngressRule(Peer.Ipv4(...), Port.HTTPS, ...);
securityGroup.AddIngressRule(Peer.Ipv4(...), Port.HTTPS, ...);
// Se crean reglas de egress para HTTP y HTTPS a internet...
securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTP, ...);
securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTPS, ...);

// Se crean reglas de ingress para SSH desde internet...
securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.SSH, ...);
```

### Key Pair

Se crea un Key Pair para habilitar la autenticación SSH.

<ins>Código para crear Key Pair:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

// Se crea Key Pair para conexiones SSH...
IKeyPair keyPair = new KeyPair(this, ..., new KeyPairProps { 
    KeyPairName = ...,
});
```

### Instancia EC2

Se crea la instancia EC2 que ofrecerá el servicio NAT para las subnets privadas con acceso a internet. Además, se configura UserData con los comandos necesarios para habilitar el ruteo y enmascaramiento de IP privadas.

<ins>Código para crear Instancia EC2:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

// Se crea User Data para la instancia...
UserData userData = UserData.ForLinux();
userData.AddCommands(
    // Se instala iptables...
    "yum install -y iptables-services",
    "systemctl enable iptables",
    "systemctl start iptables",

    // Se activa ip_forward...
    "touch /etc/sysctl.d/custom-ip-forwarding.conf",
    "chmod 666 /etc/sysctl.d/custom-ip-forwarding.conf",
    "echo \"net.ipv4.ip_forward=1\" >> /etc/sysctl.d/custom-ip-forwarding.conf",
    "sysctl -p /etc/sysctl.d/custom-ip-forwarding.conf",

    // Se crea regla de ruteo y enmascaramiento de IP privada...
    "iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE",
    "iptables -F FORWARD",
    "service iptables save"
);

// Se crea la instancia NAT...
Instance_ natInstance = new Instance_(this, ..., new InstanceProps {
    InstanceName = ...,
    InstanceType = new InstanceType(...),
    MachineImage = MachineImage.LatestAmazonLinux2023(new AmazonLinux2023ImageSsmParameterProps { 
        CpuType = AmazonLinuxCpuType.ARM_64,
    }),
    Vpc = vpc,
    VpcSubnets = new SubnetSelection {
        Subnets = [subnet1, subnet2],
    },
    UserData = userData,
    SecurityGroup = securityGroup,
    SourceDestCheck = false,
    KeyPair = keyPair,
});
```

### Ruta en Tabla de Enrutamiento

Por último, se crea nueva ruta en tablas de enrutamiento de las subnets privadas para dirigir todo el tráfico con destino a internet hacia la instancia EC2.

<ins>Código para crear Ruta:</ins>

```csharp
using Amazon.CDK.AWS.EC2;

// Se actualizan las routes tables de las subnets privadas para apuntar a la instancia...
new CfnRoute(this, ..., new CfnRouteProps {
    RouteTableId = ...,
    DestinationCidrBlock = "0.0.0.0/0",
    InstanceId = natInstance.InstanceId,
});
```

## Despliegue

El despliegue se lleva a cabo mediante GitHub Actions, para ello se configura la receta de despliegue con los siguientes pasos:

| Paso | Comando | Descripción |
|------|---------|-------------|
| Checkout Repositorio | `actions/checkout@v4` | Se descarga el repositorio en runner. |
| Instalar .NET | `actions/setup-dotnet@v4` | Se instala .NET en el runner. |
| Instalar Node.js | `actions/setup-node@v4` | Se instala Node.js en el runner. | 
| Instalar AWS CDK | `npm install -g aws-cdk` | Se instala aws-cdk con NPM. |
| Configure AWS Credentials | `aws-actions/configure-aws-credentials` | Se configuran credenciales para despliegue en AWS. |
| CDK Synth | `cdk synth` | Se sintetiza la aplicación CDK. |
| CDK Diff | `cdk --app cdk.out diff` | Se obtienen las diferencias entre nueva versión y versión desplegada. |
| CDK Deploy | `cdk --app cdk.out deploy --require-approval never` | Se despliega la aplicación CDK. |

### Variables y Secretos de Entorno

A continuación se presentan las variables que se deben configurar en el Environment para el correcto despliegue:

| Variable de Entorno | Tipo | Descripción |
|---------------------|------|-------------|
| `VERSION_DOTNET` | Variable | Versión del .NET del CDK. Por ejemplo "8". |
| `VERSION_NODEJS` | Variable | Versión de Node.js. Por ejemplo "20". |
| `ARN_GITHUB_ROLE` | Variable | ARN del Rol en IAM que se usará para el despliegue. |
| `ACCOUNT_AWS` | Variable | ID de la cuenta AWS donde desplegar. |
| `REGION_AWS` | Variable | Región primaria donde desplegar. Por ejemplo "us-west-1". |
| `DIRECTORIO_CDK` | Variable | Directorio donde se encuentra archivo cdk.json. En este caso sería ".". |
| `APP_NAME` | Variable | El nombre de la aplicación a desplegar. |
| `VPC_ID` | Variable | ID de la VPC donde se desplegará la instancia EC2. |
| `SUBNET_ID_1` | Variable | ID de la subnet pública donde se desplegará la instancia EC2. |
| `SUBNET_ID_2` | Variable | ID de la subnet pública donde se desplegará la instancia EC2. |
| `SUBNET_AZ_1` | Variable | Zona de disponibilidad de la subnet pública 1. Por ejemplo "us-west-1b". |
| `SUBNET_AZ_2` | Variable | Zona de disponibilidad de la subnet pública 2. Por ejemplo "us-west-1c". |
| `INSTANCE_TYPE` | Variable | Tipo de instancia a desplegar. Por ejemplo "t4g.nano". |
| `SUBNET_CIDR_1` | Variable | CIDR de la subnet privada con acceso a internet. |
| `SUBNET_CIDR_2` | Variable | CIDR de la subnet privada con acceso a internet. |
| `ROUTE_TABLE_ID` | Variable | ID de la tabla de enrutamiento de las redes privadas con acceso a internet. |