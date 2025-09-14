using Amazon.CDK;
using Amazon.CDK.AWS.CertificateManager;
using Amazon.CDK.AWS.CloudFront;
using Amazon.CDK.AWS.CloudFront.Origins;
using Amazon.CDK.AWS.CloudWatch;
using Amazon.CDK.AWS.CloudWatch.Actions;
using Amazon.CDK.AWS.EC2;
using Amazon.CDK.AWS.Events.Targets;
using Amazon.CDK.AWS.IAM;
using Amazon.CDK.AWS.Logs;
using Amazon.CDK.AWS.Route53;
using Amazon.CDK.AWS.Route53.Targets;
using Amazon.CDK.AWS.S3;
using Amazon.CDK.AWS.SNS;
using Amazon.CDK.AWS.SNS.Subscriptions;
using Constructs;
using System;
using System.Collections.Generic;
using LogGroupProps = Amazon.CDK.AWS.Logs.LogGroupProps;

namespace BDiazENatInstance
{
    public class BDiazENatInstanceStack : Stack
    {
        internal BDiazENatInstanceStack(Construct scope, string id, IStackProps props = null) : base(scope, id, props) {
            string account = System.Environment.GetEnvironmentVariable("ACCOUNT_AWS") ?? throw new ArgumentNullException("ACCOUNT_AWS");
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

            string rdsSecurityGroupId = System.Environment.GetEnvironmentVariable("RDS_SECURITY_GROUP_ID") ?? throw new ArgumentNullException("RDS_SECURITY_GROUP_ID");

            string routeTableId = System.Environment.GetEnvironmentVariable("ROUTE_TABLE_ID") ?? throw new ArgumentNullException("ROUTE_TABLE_ID");
            string instanceType = System.Environment.GetEnvironmentVariable("INSTANCE_TYPE") ?? throw new ArgumentNullException("INSTANCE_TYPE");

            // Domain/Subdomain para DNS...
            string domainName = System.Environment.GetEnvironmentVariable("DOMAIN_NAME") ?? throw new ArgumentNullException("DOMAIN_NAME");
            string subdomainName = System.Environment.GetEnvironmentVariable("SUBDOMAIN_NAME") ?? throw new ArgumentNullException("SUBDOMAIN_NAME");

            // Parámetros para configuración de Certbot...
            string certbotEmail = System.Environment.GetEnvironmentVariable("CERTBOT_EMAIL") ?? throw new ArgumentNullException("CERTBOT_EMAIL");

            // Parámetros para configurar notificaciones...
            string notificationEmails = System.Environment.GetEnvironmentVariable("NOTIFICATION_EMAILS") ?? throw new ArgumentNullException("NOTIFICATION_EMAILS");

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
                // Se actualizan paquetes...
                "dnf upgrade -y",

                // Se crea grupo y carpeta donde las aplicaciones dejarán sus logs...
                "groupadd logreaders",
                "mkdir -p /var/log/apps",
                "chown -R ec2-user:logreaders /var/log/apps",
                "chmod -R 750 /var/log/apps",

                // Se instala cultural info...
                "dnf install -y libicu",

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

                // Se crea regla para aceptar HTTP y HTTPS...
                "iptables -I INPUT 5 -m state --state NEW  -p tcp --dport 80 -j ACCEPT",
                "iptables -I INPUT 6 -m state --state NEW  -p tcp --dport 443 -j ACCEPT",
                "service iptables save",

                // Además se instala nginx para hospedar aplicaciones web (por ahorro de costos, se usará solo una instancia EC2 como NAT y servidor web)...
                "dnf install -y nginx",

                // Se cambia el server_name de nginx según el subdomainName a utilizar...
                $"sed -i 's/server_name  _;/server_name  {subdomainName};/g' /etc/nginx/nginx.conf",

                // Se cambia formato de logformat...
                "sed -i 's/error_log \\/var\\/log\\/nginx\\/error.log notice/error_log \\/var\\/log\\/nginx\\/error.log warn/' /etc/nginx/nginx.conf",
                "sed -i 's/\\[\\$time_local\\]/\\[\\$time_iso8601\\]/g' /etc/nginx/nginx.conf",
                "sed -i 's/\"\\$http_x_forwarded_for\"/\\$server_name \\$request_uri \\$hostname \\$server_port \"\\$http_x_forwarded_for\" \"\\$http_cf_connecting_ip\" \\$http_cf_ray \\$http_cf_ipcountry/' /etc/nginx/nginx.conf",

                // Se configura logrotate a usar grupo creado anteriormente...
                "sed -i 's/create 0640 nginx root/create 0640 nginx logreaders/' /etc/logrotate.d/nginx",
                "logrotate -f /etc/logrotate.d/nginx",

                "systemctl enable nginx",
                "systemctl start nginx",

                // Se genera certificados para HTTPS
                "dnf install -y python3 python-devel augeas-devel gcc",
                "python3 -m venv /opt/certbot/",
                "/opt/certbot/bin/pip install --upgrade pip",
                "/opt/certbot/bin/pip install certbot certbot-nginx",
                "ln -s /opt/certbot/bin/certbot /usr/bin/certbot",
                $"certbot --nginx -d {subdomainName} -m {certbotEmail} --agree-tos --non-interactive",
                "systemctl reload nginx",

                // Se crea configura crond para la autorenovación del certificado...
                "dnf install -y cronie",
                "systemctl enable crond",
                "systemctl start crond",
                "echo '0 */12 * * * root /usr/bin/certbot renew --quiet' | tee /etc/cron.d/certbot",
                "systemctl reload crond",

                // Se crea hook script para recargar nginx al renovar el certificado...
                "echo '#!/bin/bash' | tee /etc/letsencrypt/renewal-hooks/deploy/reload-webserver.sh",
                "echo 'systemctl reload nginx' | tee -a /etc/letsencrypt/renewal-hooks/deploy/reload-webserver.sh",
                "chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-webserver.sh",

                // Se instala agente de cloudwatch...
                "dnf install -y amazon-cloudwatch-agent",
                "usermod -aG logreaders cwagent",
                $"echo '{{ \"agent\": {{ \"metrics_collection_interval\": 60, \"run_as_user\": \"cwagent\" }}, \"metrics\": {{ \"aggregation_dimensions\": [ [ \"InstanceId\" ] ], \"append_dimensions\": {{ \"InstanceId\": \"${{aws:InstanceId}}\" }}, \"metrics_collected\": {{ \"disk\": {{ \"measurement\": [ \"used_percent\" ], \"metrics_collection_interval\": 60, \"resources\": [ \"*\" ] }}, \"mem\": {{ \"measurement\": [ \"mem_used_percent\" ], \"metrics_collection_interval\": 60 }} }} }}, \"logs\": {{ \"logs_collected\": {{ \"files\": {{ \"collect_list\": [ {{ \"file_path\": \"/var/log/nginx/access.log\", \"log_group_name\": \"/aws/ec2/{appName}/nginx/access-log\", \"log_stream_name\": \"{{instance_id}}-access\", \"timestamp_format\": \"[%Y-%m-%dT%H:%M:%S%z]\" }}, {{ \"file_path\": \"/var/log/nginx/error.log\", \"log_group_name\": \"/aws/ec2/{appName}/nginx/error-log\", \"log_stream_name\": \"{{instance_id}}-error\", \"timestamp_format\": \"%Y/%m/%d %H:%M:%S\" }}, {{ \"file_path\": \"/var/log/apps/*/*.log\", \"log_group_name\": \"/aws/ec2/{appName}/apps/{{folder_name}}\", \"log_stream_name\": \"{{instance_id}}-{{file_name}}\", \"timestamp_format\": \"%Y-%m-%dT%H:%M:%S\" }} ] }} }} }} }}' | tee /opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json",
                "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json"
            );

            // Se crea security group...
            SecurityGroup securityGroup = new (this, $"{appName}NatInstanceSecurityGroup", new SecurityGroupProps {
                Vpc = vpc,
                SecurityGroupName = $"{appName}NatInstanceAndWebServerSecurityGroup",
                Description = $"Security Group for NAT Instance and Web Server - {appName}",
            });
            // Se crean reglas de ingress para HTTP desde redes privadas con internet...
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr1), Port.HTTP, $"Allow HTTP from {subnetCidr1}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr2), Port.HTTP, $"Allow HTTP from {subnetCidr2}");
            // Se crean reglas de ingress para HTTPS desde redes privadas con internet...
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr1), Port.HTTPS, $"Allow HTTPS from {subnetCidr1}");
            securityGroup.AddIngressRule(Peer.Ipv4(subnetCidr2), Port.HTTPS, $"Allow HTTPS from {subnetCidr2}");

            // Se crean reglas de ingress para SSH desde internet...
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.SSH, $"Allow SSH from anywhere");

            // Se crean reglas para aplicaciones web...
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.HTTP, $"Allow HTTP from anywhere");
            securityGroup.AddIngressRule(Peer.AnyIpv4(), Port.HTTPS, $"Allow HTTPS from anywhere");

            // Se agrega permiso para acceder a RDS...
            ISecurityGroup rdsSecurityGroup = SecurityGroup.FromSecurityGroupId(this, $"{appName}RDSSecurityGroup", rdsSecurityGroupId);
            rdsSecurityGroup.AddIngressRule(securityGroup, Port.POSTGRES, "Allow connection from Nat Instance and Web Server");

            // Se crea Key Pair para conexiones SSH...
            IKeyPair keyPair = new KeyPair(this, $"{appName}NatInstanceKeyPair", new KeyPairProps {
                KeyPairName = $"{appName}NatInstanceAndWebServerKeyPair",
            });

            // Se crea log group para nginx...
            _ = new LogGroup(this, $"{appName}NginxAccessLogGroup", new LogGroupProps {
                LogGroupName = $"/aws/ec2/{appName}/nginx/access-log",
                Retention = RetentionDays.ONE_MONTH,
                RemovalPolicy = RemovalPolicy.DESTROY
            });
            _ = new LogGroup(this, $"{appName}NginxErrorLogGroup", new LogGroupProps {
                LogGroupName = $"/aws/ec2/{appName}/nginx/error-log",
                Retention = RetentionDays.ONE_MONTH,
                RemovalPolicy = RemovalPolicy.DESTROY
            });

            Role role = new(this, $"{appName}NatInstanceRole", new RoleProps {
                RoleName = $"{appName}NatInstanceAndWebServerRole",
                Description = $"Role para Instancia NAT y Web Server de {appName}",
                AssumedBy = new ServicePrincipal("ec2.amazonaws.com"),
                ManagedPolicies = [
                    ManagedPolicy.FromAwsManagedPolicyName("CloudWatchAgentServerPolicy"),
                    ManagedPolicy.FromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
                ],
                InlinePolicies = new Dictionary<string, PolicyDocument> {
                    {
                        $"{appName}NatInstanceAndWebServerPolicy",
                        new PolicyDocument(new PolicyDocumentProps{
                            Statements = [
                                new PolicyStatement(new PolicyStatementProps{
                                    Sid = $"{appName}AssumeOtherRoles",
                                    Actions = [
                                        "sts:AssumeRole"
                                    ],
                                    Resources = [
                                        $"arn:aws:iam::{account}:role/{appName}-NatInstanceWebServer-SubRole-*",
                                    ],
                                }),
                                new PolicyStatement(new PolicyStatementProps{
                                    Sid = $"{appName}DenyToOtherCloudWatch",
                                    Effect = Effect.DENY,
                                    Actions = [
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                        "logs:PutRetentionPolicy",
                                    ],
                                    NotResources = [
                                        $"arn:aws:logs:{this.Region}:{this.Account}:log-group:/aws/ec2/{appName}/*",
                                        $"arn:aws:logs:{this.Region}:{this.Account}:log-group:/aws/ec2/{appName}/*:log-stream:*"
                                    ],
                                }),
                                new PolicyStatement(new PolicyStatementProps{
                                    Sid = $"{appName}DenyToCreateGroupsCloudWatch",
                                    Effect = Effect.DENY,
                                    Actions = [
                                        "logs:CreateLogGroup",
                                    ],
                                    Resources = [
                                        $"*",
                                    ],
                                }),
                            ]
                        })
                    }
                }
            });

            // Se crea la instancia NAT...
            Instance_ natInstance = new(this, $"{appName}NatInstance", new InstanceProps {
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
                Role = role,
                DetailedMonitoring = true,
            });

            // Se crea una IP elastica para la instancia y el DNS...
            CfnEIP elasticIp = new(this, $"{appName}ElasticIP", new CfnEIPProps { 
                Tags = [
                    new CfnTag {
                        Key = "Name",
                        Value = $"{appName}NatAndWebServerElasticIP"
                    },
                ]
            });

            _ = new CfnEIPAssociation(this, $"{appName}ElasticIPAssociation", new CfnEIPAssociationProps { 
                AllocationId = elasticIp.AttrAllocationId,
                InstanceId = natInstance.InstanceId
            });

            IHostedZone hostedZone = HostedZone.FromLookup(this, $"{appName}WebServerHostedZone", new HostedZoneProviderProps {
                DomainName = domainName
            });

            // Se crea record en hosted zone...
            _ = new ARecord(this, $"{appName}WebServerARecord", new ARecordProps {
                Zone = hostedZone,
                RecordName = subdomainName,
                Target = RecordTarget.FromIpAddresses(elasticIp.Ref)
            });

            // Se actualizan las routes tables de las subnets privadas para apuntar a la instancia...
            _ = new CfnRoute(this, $"{appName}NatInstanceRoute", new CfnRouteProps {
                RouteTableId = routeTableId,
                DestinationCidrBlock = "0.0.0.0/0",
                InstanceId = natInstance.InstanceId,
            });

            // Se crea SNS topic para notificaciones asociadas a la instancia...
            Topic topic = new (this, $"{appName}NatInstanceSNSTopic", new TopicProps {
                TopicName = $"{appName}NatInstanceSNSTopic",
            });

            foreach (string email in notificationEmails.Split(",")) {
                topic.AddSubscription(new EmailSubscription(email));
            }

            // Se crean alarmas para la instancia, con notificación y acción...
            Alarm alarmInstanceCheck = new (this, $"{appName}InstanceCheckAlarm", new AlarmProps {
                AlarmName = $"{appName}InstanceCheckAlarm",
                AlarmDescription = $"Instance Check Alarm para {appName}",
                Metric = new Metric(new MetricProps {
                    Namespace = "AWS/EC2",
                    DimensionsMap = new Dictionary<string, string> {
                        { "InstanceId", natInstance.InstanceId }
                    },
                    MetricName = "StatusCheckFailed_Instance",
                    Period = Duration.Minutes(1),
                }),
                ComparisonOperator = ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                Threshold = 1,
                EvaluationPeriods = 5,
            });
            alarmInstanceCheck.AddAlarmAction(new SnsAction(topic));
            alarmInstanceCheck.AddAlarmAction(new Ec2Action(Ec2InstanceAction.REBOOT));

            Alarm alarmSystemCheck = new (this, $"{appName}SystemCheckAlarm", new AlarmProps {
                AlarmName = $"{appName}SystemCheckAlarm",
                AlarmDescription = $"System Check Alarm para {appName}",
                Metric = new Metric(new MetricProps {
                    Namespace = "AWS/EC2",
                    DimensionsMap = new Dictionary<string, string> {
                        { "InstanceId", natInstance.InstanceId }
                    },
                    MetricName = "StatusCheckFailed_System",
                    Period = Duration.Minutes(1),
                }),
                ComparisonOperator = ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                Threshold = 1,
                EvaluationPeriods = 5,
            });
            alarmSystemCheck.AddAlarmAction(new SnsAction(topic));
            alarmSystemCheck.AddAlarmAction(new Ec2Action(Ec2InstanceAction.RECOVER));
        }
    }
}
