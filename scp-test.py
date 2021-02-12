import pprint
import json
import boto3
import sys
import os
from dbconnection import get_crendentails
import socket
socket.getaddrinfo('eadha-docker.cutn3y51xkog.us-west-2.rds.amazonaws.com', 3306)

pp = pprint.PrettyPrinter(indent=1)
policy = { "jk": {
  "Version": "2012-10-17",
  "Statement": "null"
}
}
key = { "JS-AWS-P-0016" :{
            "Action": [
                "ec2:DeleteFlowLogs",
                "logs:DeleteLogGroup",
                "logs:DeleteLogStream"
            ],
            "Resource": "*",
            "Effect": "Deny"
        },

"JS-AWS-P-0017" : {
                        "Action": [
                                "ec2:CreateNatGateway",
                                "ec2:CreateInternetGateway",
                                "ec2:DeleteNatGateway",
                                "ec2:AttachInternetGateway",
                                "ec2:DeleteInternetGateway",
                                "ec2:DetachInternetGateway",
                                "ec2:CreateClientVpnRoute",
                                "ec2:AttachVpnGateway",
                                "ec2:DisassociateClientVpnTargetNetwork",
                                "ec2:DeleteClientVpnEndpoint",
                                "ec2:DeleteVpcPeeringConnection",
                                "ec2:AcceptVpcPeeringConnection",
                                "ec2:CreateNatGateway",
                                "ec2:ModifyClientVpnEndpoint",
                                "ec2:CreateVpnConnectionRoute",
                                "ec2:RevokeClientVpnIngress",
                                "ec2:RejectVpcPeeringConnection",
                                "ec2:DetachVpnGateway",
                                "ec2:DeleteVpnConnectionRoute",
                                "ec2:CreateClientVpnEndpoint",
                                "ec2:AuthorizeClientVpnIngress",
                                "ec2:DeleteVpnGateway",
                                "ec2:TerminateClientVpnConnections",
                                "ec2:DeleteClientVpnRoute",
                                "ec2:ModifyVpcPeeringConnectionOptions",
                                "ec2:CreateVpnGateway",
                                "ec2:DeleteNatGateway",
                                "ec2:DeleteVpnConnection",
                                "ec2:CreateVpcPeeringConnection",
                                "ec2:CreateVpnConnection",
                                "directconnect:CreatePrivateVirtualInterface",
                                "directconnect:DeleteBGPPeer",
                                "directconnect:DeleteLag",
                                "directconnect:AssociateHostedConnection",
                                "directconnect:CreateInterconnect",
                                "directconnect:CreatePublicVirtualInterface",
                                "directconnect:CreateLag",
                                "directconnect:CreateDirectConnectGateway",
                                "directconnect:AssociateVirtualInterface",
                                "directconnect:AllocateConnectionOnInterconnect",
                                "directconnect:AssociateConnectionWithLag",
                                "directconnect:AllocatePrivateVirtualInterface",
                                "directconnect:DeleteInterconnect",
                                "directconnect:AllocateHostedConnection",
                                "directconnect:DeleteDirectConnectGateway",
                                "directconnect:DeleteVirtualInterface",
                                "directconnect:DeleteDirectConnectGatewayAssociation",
                                "directconnect:CreateDirectConnectGatewayAssociation",
                                "directconnect:DeleteConnection",
                                "directconnect:CreateBGPPeer",
                                "directconnect:AllocatePublicVirtualInterface",
                                "directconnect:CreateConnection",
                                "globalaccelerator:DeleteListener",
                                "globalaccelerator:DeleteAccelerator",
                                "globalaccelerator:UpdateListener",
                                "globalaccelerator:UpdateAccelerator",
                                "globalaccelerator:CreateEndpointGroup",
                                "globalaccelerator:UpdateAcceleratorAttributes",
                                "globalaccelerator:UpdateEndpointGroup",
                                "globalaccelerator:CreateListener",
                                "globalaccelerator:CreateAccelerator",
                                "globalaccelerator:DeleteEndpointGroup"
                        ],
                        "Resource": [
                                "*"
                        ],
                        "Effect": "Deny"
                },
"JS-AWS-P-0018" : {
            "Action": [
                "securityhub:DeleteInvitations",
                "securityhub:DisableSecurityHub",
                "securityhub:DisassociateFromMasterAccount",
                "securityhub:DeleteMembers",
                "securityhub:DisassociateMembers"
            ],
            "Resource": "*",
            "Effect": "Deny"
},
"JS-AWS-P-0019" :  {
            "Action": [
                "s3:DeleteBucket",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
            ],
            "Resource": "*",
            "Effect": "Deny"
},
"JS-AWS-P-0020" :  {
            "Action": "*",
            "Resource": "*",
            "Effect": "Deny",
            "Condition": {
                "StringLike": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::*:root"
                    ]
                }
            }
},
"JS-AWS-P-0022" : {
            "NotAction": [
                "a4b:*",
                "acm:*",
                "aws-marketplace-management:*",
                "aws-marketplace:*",
                "aws-portal:*",
                "awsbillingconsole:*",
                "budgets:*",
                "ce:*",
                "chime:*",
                "cloudfront:*",
                "config:*",
                "cur:*",
                "directconnect:*",
                "ec2:DescribeRegions",
                "ec2:DescribeTransitGateways",
                "ec2:DescribeVpnGateways",
                "fms:*",
                "globalaccelerator:*",
                "health:*",
                "iam:*",
                "importexport:*",
                "kms:*",
                "mobileanalytics:*",
                "networkmanager:*",
                "organizations:*",
                "pricing:*",
                "route53:*",
                "route53domains:*",
                "s3:GetAccountPublic*",
                "s3:ListAllMyBuckets",
                "s3:PutAccountPublic*",
                "shield:*",
                "sts:*",
                "support:*",
                "trustedadvisor:*",
                "waf-regional:*",
                "waf:*",
                "wafv2:*",
                "wellarchitected:*"
            ],
            "Resource": "*",
            "Effect": "Deny",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": [
                        "us-east-1",
                        "us-west-1"
                    ]
                }
            }
        }
}
def scp_creating_policy(kl,client,argumentList):
    kl = kl[1:-1].split(",")

    # from juno.schema import validate, StructureParser
    l =[]
    print("""\n......................//////.....................................\nType "JS-AWS-P-0016" for creating the policy "vpc Prevent Users from Deleting Amazon VPC Flow Logs"
Type "JS-AWS-P-0017" for creating the policy "Protect VPC Connectivity Settings from Modification"
Type "JS-AWS-P-0018" for creating the policy "Prevent Users from Disabling AWS Security Hub in an account"
Type "JS-AWS-P-0019" for creating the policy "Prevent Users from Deleting S3 Buckets or Objects"
Type "JS-AWS-P-0020" for creating the policy "Restrict the Use of the Root User in an AWS Account"
Type "JS-AWS-P-0022" for creating the policy "Restrict Region Based Access"
    \nType exit to exit\n
    *Note: Enter space separated identifiers if you want to run more than one policy\n""")
    # n=list(set(input("Enter: " ).split()))
    print(os.environ["AWS_ACCESS_KEY_ID"],os.environ["AWS_SECRET_ACCESS_KEY"])
    for i in kl:
        l.append(key[i])
    policy['jk']['Statement'] = l
    # print(l)
    # print(type(policy))
    # pp.pprint(policy['jk'])
    # a = json.dumps(policy)
    # print(type(a))
    # pp.pprint(a)
    # name = input("Enter the policy name: ")
    # description=input("Enter the description:")
    response = client.create_policy(
        # Content='{\"Version\": \"2012-10-17\",\"Statement\": [\{\"Action\": \"*\",\"Resource\": \"*\",\"Effect\": \"Deny\",\"Condition\": {\"StringLike\": {\"aws:PrincipalArn\": [\"arn:aws:iam::006555710886:user/radha\"]}}}]}',
        Content= json.dumps(policy['jk']),
        Description= "created through docker",
        Name= argumentList[-5],
        Type='SERVICE_CONTROL_POLICY'
    )
def scp_pop_policy(kl,client,argumentList):
    print("""\n......................//////.....................................\n
Type "JS-AWS-P-0016" to delete the policy "vpc Prevent Users from Deleting Amazon VPC Flow Logs"
Type "JS-AWS-P-0017" to delete the policy "Protect VPC Connectivity Settings from Modification"
Type "JS-AWS-P-0018" to delete the policy "Prevent Users from Disabling AWS Security Hub in an account"
Type "JS-AWS-P-0019" to delete the policy "Prevent Users from Deleting S3 Buckets or Objects"
Type "JS-AWS-P-0020" to delete the policy "Restrict the Use of the Root User in an AWS Account"
Type "JS-AWS-P-0022" to delete the policy "Restrict Region Based Access"
    \nType exit to exit\n
    *Note: Enter space separated identifiers if you want to delete more than one policy\n""")
    # id=list(set(input("Enter: " ).split()))
    # print(id)
    p=argumentList[-5]
    response = client.describe_policy(
        PolicyId=p
    )
    kl = kl[1:-1].split(",")
    # pp.pprint(response)
    l = response['Policy']['Content']
    l= json.loads(l)
    leng = len(l['Statement'])
    count = 0
    for i in kl:
        #print(key[i])
        if count == leng -1:
            raise Exception('Only one statement is present,Atleast one statement should be there cannot delete')
    # res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}
        elif key[i] in l['Statement']:
            #print(key[i],l['Statement'])
            l['Statement'].remove(key[i])
            count = count + 1
    l= json.dumps(l)
    # print(type(l))
    response1 = client.update_policy(
        PolicyId=p,
        Content=l
    )
print("Press 1 to create policies\nPress 2 to update policies\npress 3 to exit\n")
def input():
    argumentList = sys.argv
    REGION_NAME = argumentList[-4]
    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = get_crendentails(argumentList[-1])
    print(ACCESS_KEY,SECRET_KEY)
    os.environ["AWS_ACCESS_KEY_ID"] = ACCESS_KEY
    os.environ["AWS_SECRET_ACCESS_KEY"] = SECRET_KEY
    client = boto3.client('organizations',region_name=REGION_NAME,aws_access_key_id= os.environ["AWS_ACCESS_KEY_ID"] ,aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],aws_session_token=SESSION_TOKEN)
    if SESSION_TOKEN:
        os.environ["AWS_SESSION_TOKEN"] = SESSION_TOKEN
    x=int(argumentList[-2])
    kl= argumentList[-3]
    if x == 1:
      scp_creating_policy(kl,client,argumentList)
    elif x == 2:
      scp_pop_policy(kl,client,argumentList)
    elif x == 3:
      print("exiting.....")
    exit()
input()
