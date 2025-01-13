from z3 import *
import json

def create_instance_type_constraint(instance_types):
    """Creates Z3 constraints for allowed instance types"""
    s = Solver()
    
    # Create a string type for instance types
    Instance = String('instance')
    
    # Create a boolean for whether the action is allowed
    is_allowed = Bool('is_allowed')
    
    # The instance type must be one of the allowed types
    instance_constraint = Or([Instance == StringVal(t) for t in instance_types])
    
    # If the action is allowed, the instance type must be valid
    s.add(Implies(is_allowed, instance_constraint))
    
    return s

def parse_prompt_policy(prompt):
    """Parse a policy in your prompting language"""
    # Simple parser for now - assumes format "ALLOW user:X RunInstances type1,type2"
    parts = prompt.split()
    if len(parts) >= 4 and parts[0] == "ALLOW" and parts[2] == "RunInstances":
        instance_types = parts[3].split(',')
        return instance_types
    return []

def parse_aws_policy(policy_json):
    """Parse an AWS policy JSON for instance type restrictions"""
    policy = json.loads(policy_json)
    
    # Add debug print to see the policy structure
    print(f"Parsed AWS policy structure: {policy}")
    
    if isinstance(policy, dict):  # If it's a single statement
        statement = policy
        if (statement.get("Action") == ["ec2:RunInstances"] and
            "Condition" in statement and
            "StringEquals" in statement["Condition"] and
            "ec2:InstanceType" in statement["Condition"]["StringEquals"]):
            
            return statement["Condition"]["StringEquals"]["ec2:InstanceType"]
    
    return []

def policies_are_equivalent(prompt_policy, aws_policy_json):
    """Check if the prompt policy and AWS policy are equivalent"""
    prompt_types = parse_prompt_policy(prompt_policy)
    aws_types = parse_aws_policy(aws_policy_json)
    
    # If the allowed instance types are different, policies aren't equivalent
    if set(prompt_types) != set(aws_types):
        return False
    
    # Create Z3 constraints for both policies
    prompt_solver = create_instance_type_constraint(prompt_types)
    aws_solver = create_instance_type_constraint(aws_types)
    
    # Check if the constraints are equivalent
    # If one solver is satisfiable and the other isn't, they're not equivalent
    return (prompt_solver.check() == aws_solver.check())

# Example usage
prompt = "ALLOW user:developer RunInstances t2.micro,t2.small"
aws_policy = """{
    "Sid": "LimitInstanceTypes",
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:instance/*"],
    "Condition": {
        "StringEquals": {
            "ec2:InstanceType": ["t2.micro", "t2.small"]
        }
    }
}"""

# Add debug prints
print("Parsing prompt policy...")
prompt_types = parse_prompt_policy(prompt)
print(f"Found instance types from prompt: {prompt_types}")

print("\nParsing AWS policy...")
aws_types = parse_aws_policy(aws_policy)
print(f"Found instance types from AWS policy: {aws_types}")

print("\nChecking equivalence...")
are_equivalent = policies_are_equivalent(prompt, aws_policy)
print(f"Policies are equivalent: {are_equivalent}")