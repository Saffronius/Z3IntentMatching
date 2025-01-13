# AWS IAM Policy Validator

A Python-based tool that validates and compares AWS IAM policies using the Z3 theorem prover. This tool can verify equivalence between a simplified policy language and AWS IAM JSON policies.

## Features

- Convert simplified policy language to AWS IAM policy format
- Validate policy equivalence using Z3 theorem prover
- Support for multiple AWS EC2 policy conditions:
  - Instance type restrictions
  - Volume size limits
  - String equality conditions
  - Numeric comparisons
  - Basic ARN pattern matching

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd aws-iam-validator
```

2. Install dependencies:
```bash
pip install z3-solver
```

## Usage

### Basic Policy Validation

```python
from basic import policies_are_equivalent

# Example policies
prompt_policy = "ALLOW user:developer RunInstances t2.micro,t2.small"
aws_policy = """
{
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:instance/*"],
    "Condition": {
        "StringEquals": {
            "ec2:InstanceType": ["t2.micro", "t2.small"]
        }
    }
}
"""

# Check if policies are equivalent
result = policies_are_equivalent(prompt_policy, aws_policy)
print(f"Policies are equivalent: {result}")
```

### Advanced Policy Validation

```python
from basic1 import PolicyValidator

validator = PolicyValidator()

# Example with volume size restrictions
prompt = "ALLOW user:developer RunInstances LIMIT VolumeSize 16"
aws_policy = {
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:volume/*"],
    "Condition": {
        "NumericLessThanEquals": {
            "ec2:VolumeSize": "16"
        }
    }
}

result = validator.policies_are_equivalent(prompt, aws_policy)
```

## Supported Policy Formats

### Simplified Policy Language
- Basic format: `ALLOW user:<role> RunInstances <conditions>`
- Instance type restrictions: `t2.micro,t2.small`
- Volume size limits: `LIMIT VolumeSize <size>`

### AWS IAM Policy Format
- Standard JSON IAM policy structure
- Supports conditions:
  - StringEquals
  - NumericLessThanEquals
  - StringLike (basic wildcard patterns)

## Implementation Details

The tool uses Z3 theorem prover to:
- Convert policy statements into logical constraints
- Create symbolic variables for actions, resources, and conditions
- Compare logical equivalence of policies

## Testing

The project includes several test cases:
1. Matching instance type restrictions
2. Matching volume size limits
3. Mismatched policies validation

Run tests using the example code in `basic1.py`.

## License

[Choose an appropriate license]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
```

This README provides a comprehensive overview of your project, focusing on the core functionality shown in basic.py and basic1.py. It includes installation instructions, usage examples, and explains the supported policy formats. Feel free to modify any section to better match your project's specific needs!
