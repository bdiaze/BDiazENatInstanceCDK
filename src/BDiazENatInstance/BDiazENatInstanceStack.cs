using Amazon.CDK;
using Amazon.CDK.AWS.EC2;
using Constructs;

namespace BDiazENatInstance
{
    public class BDiazENatInstanceStack : Stack
    {
        internal BDiazENatInstanceStack(Construct scope, string id, IStackProps props = null) : base(scope, id, props) {
            string appName = System.Environment.GetEnvironmentVariable("APP_NAME")!;
            string vpcId = System.Environment.GetEnvironmentVariable("VPC_ID");
            string subnetId1 = System.Environment.GetEnvironmentVariable("SUBNET_ID_1")!;
            string subnetId2 = System.Environment.GetEnvironmentVariable("SUBNET_ID_2")!;
            string subnetCidr1 = System.Environment.GetEnvironmentVariable("SUBNET_CIDR_1")!;
            string subnetCidr2 = System.Environment.GetEnvironmentVariable("SUBNET_CIDR_2")!;
            string routeTableId = System.Environment.GetEnvironmentVariable("ROUTE_TABLE_ID")!;
            string instanceType = System.Environment.GetEnvironmentVariable("INSTANCE_TYPE");
            string imageName = System.Environment.GetEnvironmentVariable("IMAGE_NAME");

            // Se obtiene referencia a la VPC...
            IVpc vpc = Vpc.FromLookup(this, "Vpc", new VpcLookupOptions {
                VpcId = vpcId
            });

            //Se obtienen referencias a las subredes privadas...
            ISubnet subnet1 = Subnet.FromSubnetAttributes(this, $"{appName}Subnet1", new SubnetAttributes { 
                SubnetId = subnetId1,
                Ipv4CidrBlock = subnetCidr1,
            });
            ISubnet subnet2 = Subnet.FromSubnetAttributes(this, $"{appName}Subnet2", new SubnetAttributes { 
                SubnetId = subnetId2,
                Ipv4CidrBlock = subnetCidr2
            });

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

            // Se crea security group...
            ISecurityGroup securityGroup = new SecurityGroup(this, $"{appName}NatInstanceSecurityGroup", new SecurityGroupProps {
                Vpc = vpc,
                SecurityGroupName = $"{appName}NatInstanceSecurityGroup",
                Description = $"Security Group for NAT Instance - {appName}",
                AllowAllOutbound = false,
            });
            // Se crean reglas de ingress para HTTP desde redes privadas...
            securityGroup.AddIngressRule(Peer.Ipv4(subnet1.Ipv4CidrBlock), Port.HTTP, $"Allow HTTP from {subnet1.Ipv4CidrBlock}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnet2.Ipv4CidrBlock), Port.HTTP, $"Allow HTTP from {subnet2.Ipv4CidrBlock}");
            // Se crean reglas de ingress para HTTPS desde redes privadas...
            securityGroup.AddIngressRule(Peer.Ipv4(subnet1.Ipv4CidrBlock), Port.HTTPS, $"Allow HTTPS from {subnet1.Ipv4CidrBlock}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnet2.Ipv4CidrBlock), Port.HTTPS, $"Allow HTTPS from {subnet2.Ipv4CidrBlock}");
            // Se crean reglas de egress para HTTP y HTTPS a internet...
            securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTP, "Allow HTTP to anywhere");
            securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTPS, "Allow HTTPS to anywhere");

            // Se crea la instancia NAT...
            Instance_ natInstance = new Instance_(this, $"{appName}NatInstance", new InstanceProps {
                InstanceName = $"{appName}NatInstance",
                InstanceType = new InstanceType(instanceType),
                MachineImage = MachineImage.Lookup(new LookupMachineImageProps {
                    Name = imageName
                }),
                Vpc = vpc,
                VpcSubnets = new SubnetSelection {
                    Subnets = [subnet1, subnet2]
                },
                UserData = userData,
                SecurityGroup = securityGroup,
                SourceDestCheck = false,
            });

            // Se actualizan las routes tables de las subnets privadas para apuntar a la instancia...
            new CfnRoute(this, $"{appName}NatInstanceRoute", new CfnRouteProps {
                RouteTableId = routeTableId,
                DestinationCidrBlock = "0.0.0.0/0",
                InstanceId = natInstance.InstanceId,
            });
        }
    }
}
