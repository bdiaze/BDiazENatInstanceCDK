using Amazon.CDK;
using Amazon.CDK.AWS.CertificateManager;
using Amazon.CDK.AWS.CloudFront;
using Amazon.CDK.AWS.CloudFront.Origins;
using Amazon.CDK.AWS.EC2;
using Amazon.CDK.AWS.Route53;
using Amazon.CDK.AWS.Route53.Targets;
using Constructs;
using System;

namespace BDiazENatInstance
{
    public class BDiazENatInstanceStack : Stack
    {
        internal BDiazENatInstanceStack(Construct scope, string id, IStackProps props = null) : base(scope, id, props) {
            string appName = System.Environment.GetEnvironmentVariable("APP_NAME") ?? throw new ArgumentNullException("APP_NAME");
            string vpcId = System.Environment.GetEnvironmentVariable("VPC_ID") ?? throw new ArgumentNullException("VPC_ID");
            // Subnets públicas para instancia NAT...
            string subnetId1 = System.Environment.GetEnvironmentVariable("SUBNET_ID_1") ?? throw new ArgumentNullException("SUBNET_ID_1");
            string subnetId2 = System.Environment.GetEnvironmentVariable("SUBNET_ID_2") ?? throw new ArgumentNullException("SUBNET_ID_2");
            string subnetAz1 = System.Environment.GetEnvironmentVariable("SUBNET_AZ_1") ?? throw new ArgumentNullException("SUBNET_AZ_1");
            string subnetAz2 = System.Environment.GetEnvironmentVariable("SUBNET_AZ_2") ?? throw new ArgumentNullException("SUBNET_AZ_2");

            // CIDR de subnet privada para reglas de ingress de security group...
            string subnetCidr1 = System.Environment.GetEnvironmentVariable("SUBNET_CIDR_1") ?? throw new ArgumentNullException("SUBNET_CIDR_1");
            string subnetCidr2 = System.Environment.GetEnvironmentVariable("SUBNET_CIDR_2") ?? throw new ArgumentNullException("SUBNET_CIDR_2");

            string routeTableId = System.Environment.GetEnvironmentVariable("ROUTE_TABLE_ID") ?? throw new ArgumentNullException("ROUTE_TABLE_ID");
            string instanceType = System.Environment.GetEnvironmentVariable("INSTANCE_TYPE") ?? throw new ArgumentNullException("INSTANCE_TYPE");

            // Certificado y Domain/Subdomain para distribución de cloudfront...
            string certificateArn = System.Environment.GetEnvironmentVariable("CERTIFICATE_ARN") ?? throw new ArgumentNullException("CERTIFICATE_ARN");
            string domainName = System.Environment.GetEnvironmentVariable("DOMAIN_NAME") ?? throw new ArgumentNullException("DOMAIN_NAME");
            string subdomainName = System.Environment.GetEnvironmentVariable("SUBDOMAIN_NAME") ?? throw new ArgumentNullException("SUBDOMAIN_NAME");

            // Parámetros para configuración de Certbot...
            string certbotEmail = System.Environment.GetEnvironmentVariable("CERTBOT_EMAIL") ?? throw new ArgumentNullException("CERTBOT_EMAIL");

            // Se obtiene referencia a la VPC...
            IVpc vpc = Vpc.FromLookup(this, "Vpc", new VpcLookupOptions {
                VpcId = vpcId
            });

            //Se obtienen referencias a las subredes públicas...
            ISubnet subnet1 = Subnet.FromSubnetAttributes(this, $"{appName}Subnet1", new SubnetAttributes {
                SubnetId = subnetId1,
                AvailabilityZone = subnetAz1,
            });
            ISubnet subnet2 = Subnet.FromSubnetAttributes(this, $"{appName}Subnet2", new SubnetAttributes {
                SubnetId = subnetId2,
                AvailabilityZone = subnetAz2,
            });

            // Se crea User Data para la instancia...
            UserData userData = UserData.ForLinux();
            userData.AddCommands(
                // Se actualizan paquetes
                "dnf upgrade -y",

                // Se instala iptables...
                "dnf install -y iptables-services",
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
                "service iptables save",

                // Además se instala nginx para hospedar aplicaciones web (por ahorro de costos, se usará solo una instancia EC2 como NAT y servidor web)...
                "dnf install -y nginx",
                "systemctl enable nginx",
                "systemctl start nginx",

                // Se crea regla para aceptar HTTP y HTTPS...
                "iptables -I INPUT 5 -m state --state NEW  -p tcp --dport 80 -j ACCEPT",
                "iptables -I INPUT 6 -m state --state NEW  -p tcp --dport 443 -j ACCEPT",
                "service iptables save",

                // Se instala certbot para configurar SSL...
                "dnf install -y python3 python-devel augeas-devel gcc",
                "python3 -m venv /opt/certbot/",
                "/opt/certbot/bin/pip install --upgrade pip",
                "/opt/certbot/bin/pip install certbot certbot-nginx",
                "ln -s /opt/certbot/bin/certbot /usr/bin/certbot",
                $"certbot --nginx -d {subdomainName} -m {certbotEmail} --agree-tos --non-interactive --pre-hook \"systemctl stop nginx\" --post-hook \"systemctl start nginx\""
            );

            // Se crea security group...
            ISecurityGroup securityGroup = new SecurityGroup(this, $"{appName}NatInstanceSecurityGroup", new SecurityGroupProps {
                Vpc = vpc,
                SecurityGroupName = $"{appName}NatInstanceAndWebServerSecurityGroup",
                Description = $"Security Group for NAT Instance and Web Server - {appName}",
                AllowAllOutbound = false,
            });
            // Se crean reglas de ingress para HTTP desde redes privadas con internet...
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr1), Port.HTTP, $"Allow HTTP from {subnetCidr1}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr2), Port.HTTP, $"Allow HTTP from {subnetCidr2}");
            // Se crean reglas de ingress para HTTPS desde redes privadas con internet...
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr1), Port.HTTPS, $"Allow HTTPS from {subnetCidr1}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr2), Port.HTTPS, $"Allow HTTPS from {subnetCidr2}");
            // Se crean reglas de egress para HTTP y HTTPS a internet...
            securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTP, "Allow HTTP to anywhere");
            securityGroup.AddEgressRule(Peer.AnyIpv4(), Port.HTTPS, "Allow HTTPS to anywhere");

            // Se crean reglas de ingress para SSH desde internet...
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.SSH, $"Allow SSH from anywhere");

            // Se crean reglas para aplicaciones web...
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.HTTP, $"Allow HTTP from anywhere");
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.HTTPS, $"Allow HTTPS from anywhere");

            // Se crea Key Pair para conexiones SSH...
            IKeyPair keyPair = new KeyPair(this, $"{appName}NatInstanceKeyPair", new KeyPairProps {
                KeyPairName = $"{appName}NatInstanceAndWebServerKeyPair2",
            });

            // Se crea la instancia NAT...
            Instance_ natInstance = new Instance_(this, $"{appName}NatInstance", new InstanceProps {
                InstanceName = $"{appName}NatInstanceAndWebServer",
                InstanceType = new InstanceType(instanceType),
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

            // Se actualizan las routes tables de las subnets privadas para apuntar a la instancia...
            new CfnRoute(this, $"{appName}NatInstanceRoute", new CfnRouteProps {
                RouteTableId = routeTableId,
                DestinationCidrBlock = "0.0.0.0/0",
                InstanceId = natInstance.InstanceId,
            });


            ICertificate certificate = Certificate.FromCertificateArn(this, $"{appName}WebServerCertificate", certificateArn);

            IHostedZone hostedZone = HostedZone.FromLookup(this, $"{appName}WebServerHostedZone", new HostedZoneProviderProps {
                DomainName = domainName
            });

            // Se crea distribución cloudfront para instancia de web server...
            Distribution distribution = new(this, $"{appName}WebServerDistribution", new DistributionProps {
                Comment = $"{appName} Web Server Distribution",
                DomainNames = [subdomainName],
                DefaultBehavior = new BehaviorOptions {
                    Origin = new HttpOrigin(natInstance.InstancePublicDnsName, new HttpOriginProps { 
                        OriginId = $"{appName}WebServerOrigin",
                        ProtocolPolicy = OriginProtocolPolicy.MATCH_VIEWER,
                    }),
                    OriginRequestPolicy = OriginRequestPolicy.ALL_VIEWER,
                    AllowedMethods = AllowedMethods.ALLOW_ALL,
                    ViewerProtocolPolicy = ViewerProtocolPolicy.ALLOW_ALL,
                },
                Certificate = certificate,
            });

            // Se crea record en hosted zone...
            _ = new ARecord(this, $"{appName}WebServerARecord", new ARecordProps {
                Zone = hostedZone,
                RecordName = subdomainName,
                Target = RecordTarget.FromAlias(new CloudFrontTarget(distribution))
            });
        }
    }
}
