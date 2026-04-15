export function generateCloudFormationTemplate() {
  const role_arn = process.env.REACT_APP_ROLE_ARN;
  return `
AWSTemplateFormatVersion: '2010-09-09'
Description: IAM Role to allow third-party scanning account to assume role with read-only access

Resources:
  ScannerAssumeRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: Sec360-InfraScan-Role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: [
                ${role_arn}
              ]
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
      Description: Allows scanning service to assume this role and perform read-only actions

Outputs:
  RoleArn:
    Value: !GetAtt ScannerAssumeRole.Arn
    Description: ARN of the created role
`;
}
