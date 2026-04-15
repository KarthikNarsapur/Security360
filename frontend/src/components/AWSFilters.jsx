// awsFilters.js

export const regionOptions = [
  "us-east-1", // N. Virginia
  "us-east-2", // Ohio
  "us-west-1", // N. California
  "us-west-2", // Oregon
  "af-south-1", // Cape Town
  "ap-east-1", // Hong Kong
  "ap-south-1", // Mumbai
  "ap-northeast-1", // Tokyo
  "ap-northeast-2", // Seoul
  "ap-northeast-3", // Osaka
  "ap-southeast-1", // Singapore
  "ap-southeast-2", // Sydney
  "ca-central-1", // Canada Central
  "eu-central-1", // Frankfurt
  "eu-north-1", // Stockholm
  "eu-south-1", // Milan
  "eu-west-1", // Ireland
  "eu-west-2", // London
  "eu-west-3", // Paris
  "me-south-1", // Bahrain
  "sa-east-1", // São Paulo
];

export const serviceOptions = [
  "Default Vpcs",
  "ec2",
  "s3",
  "lambda",
  "rds",
  "cloudtrail",
  "cloudwatch",
  "dynamodb",
  "sns",
  "sqs",
  "api-gateway",
  "eks",
  "elasticache",
  "kms",
  "vpc",
  "route53",
];

export const severityOptions = ["Low", "Medium", "High", "Critical"];

export const groupedRegionOptions = [
  {
    label: "United States",
    options: [
      { value: "us-east-1", label: "N. Virginia (us-east-1)" },
      { value: "us-east-2", label: "Ohio (us-east-2)" },
      { value: "us-west-1", label: "N. California (us-west-1)" },
      { value: "us-west-2", label: "Oregon (us-west-2)" },
    ],
  },
  {
    label: "Asia Pacific",
    options: [
      { value: "ap-south-2", label: "Hyderabad (ap-south-2)" },
      { value: "ap-south-1", label: "Mumbai (ap-south-1)" },
      { value: "ap-northeast-3", label: "Osaka (ap-northeast-3)" },
      { value: "ap-northeast-2", label: "Seoul (ap-northeast-2)" },
      { value: "ap-southeast-1", label: "Singapore (ap-southeast-1)" },
      { value: "ap-southeast-2", label: "Sydney (ap-southeast-2)" },
      { value: "ap-northeast-1", label: "Tokyo (ap-northeast-1)" },
    ],
  },
  {
    label: "Canada",
    options: [{ value: "ca-central-1", label: "Central (ca-central-1)" }],
  },
  {
    label: "Europe",
    options: [
      { value: "eu-central-1", label: "Frankfurt (eu-central-1)" },
      { value: "eu-west-1", label: "Ireland (eu-west-1)" },
      { value: "eu-west-2", label: "London (eu-west-2)" },
      { value: "eu-west-3", label: "Paris (eu-west-3)" },
      { value: "eu-north-1", label: "Stockholm (eu-north-1)" },
    ],
  },
  {
    label: "South America",
    options: [{ value: "sa-east-1", label: "São Paulo (sa-east-1)" }],
  },
];
