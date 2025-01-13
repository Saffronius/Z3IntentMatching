from z3 import *
import json
from typing import Dict, List, Union

class PolicyValidator:
    def __init__(self):
        self.solver = Solver()
        
    def create_basic_types(self):
        """Create basic Z3 types needed for policy validation"""
        self.Action = String('action')
        self.Resource = String('resource')
        self.Effect = Bool('effect')  # True for Allow, False for Deny
        
    def create_condition_constraints(self, condition_block: Dict) -> List[ExprRef]:
        """Convert AWS IAM condition block to Z3 constraints"""
        constraints = []
        
        if not condition_block:
            return constraints
            
        for condition_type, conditions in condition_block.items():
            if condition_type == "StringEquals":
                for key, values in conditions.items():
                    if not isinstance(values, list):
                        values = [values]
                    # Create a String constant for this condition
                    condition_var = String(f"condition_{key}")
                    # The value must be one of the allowed values
                    constraints.append(Or([condition_var == StringVal(v) for v in values]))
                    
            elif condition_type == "NumericLessThanEquals":
                for key, value in conditions.items():
                    # Create a Real constant for numeric conditions
                    condition_var = Real(f"condition_{key}")
                    constraints.append(condition_var <= float(value))
                    
            elif condition_type == "StringLike":
                # Handle ARN patterns
                for key, pattern in conditions.items():
                    condition_var = String(f"condition_{key}")
                    # For now, we'll handle basic wildcard patterns
                    if pattern.endswith("*"):
                        base_pattern = pattern[:-1]
                        constraints.append(PrefixOf(StringVal(base_pattern), condition_var))
        
        return constraints

    def parse_prompt_statement(self, prompt: str) -> Dict:
        """Parse a statement in your prompting language into a structured format"""
        parts = prompt.split()
        print(f"Parsing prompt parts: {parts}")  # Debug print
        
        result = {
            "Effect": parts[0],  # ALLOW/DENY
            "Action": [],
            "Resource": [],  # Initialize as empty list instead of None
            "Condition": {}
        }
        
        # Basic parsing for RunInstances
        if "RunInstances" in parts:
            result["Action"] = ["ec2:RunInstances"]
            
            # Set appropriate resource based on the condition
            if len(parts) > 3:
                if "LIMIT" in parts and "VolumeSize" in parts:
                    result["Resource"] = ["arn:aws:ec2:*:*:volume/*"]
                else:
                    result["Resource"] = ["arn:aws:ec2:*:*:instance/*"]
            
            # Handle instance types (if specified)
            if len(parts) > 3 and not parts[3].startswith("LIMIT"):
                instance_types = parts[3].split(',')
                result["Condition"]["StringEquals"] = {
                    "ec2:InstanceType": instance_types
                }
        
        # Handle LIMIT statements
        if "LIMIT" in prompt:
            limit_idx = parts.index("LIMIT")
            if "VolumeSize" in parts:
                result["Condition"]["NumericLessThanEquals"] = {
                    "ec2:VolumeSize": parts[limit_idx + 2]
                }
        
        print(f"Parsed result: {json.dumps(result, indent=2)}")  # Debug print
        return result

    def create_statement_constraints(self, statement: Dict) -> List[ExprRef]:
        """Convert a single policy statement into Z3 constraints"""
        constraints = []
        print(f"Creating constraints for statement: {json.dumps(statement, indent=2)}")
        
        # Basic statement elements
        if statement.get("Effect") == "Allow":
            constraints.append(self.Effect == True)
        else:
            constraints.append(self.Effect == False)
            
        # Action constraints
        actions = statement.get("Action", [])
        if actions:
            constraints.append(Or([self.Action == StringVal(a) for a in actions]))
            
        # Resource constraints
        resources = statement.get("Resource", [])
        if resources:
            constraints.append(Or([self.Resource == StringVal(r) for r in resources]))
            
        # Condition constraints
        if "Condition" in statement:
            constraints.extend(self.create_condition_constraints(statement["Condition"]))
            
        return constraints

    def policies_are_equivalent(self, prompt_policy: str, aws_policy: Dict) -> bool:
        """Check if a prompt policy and AWS policy are equivalent"""
        self.create_basic_types()
        
        # Parse and create constraints for prompt policy
        prompt_statement = self.parse_prompt_statement(prompt_policy)
        prompt_constraints = self.create_statement_constraints(prompt_statement)
        
        # Create constraints for AWS policy
        aws_constraints = self.create_statement_constraints(aws_policy)
        
        # Add constraints to solver
        s1 = Solver()
        s2 = Solver()
        
        for c in prompt_constraints:
            s1.add(c)
        for c in aws_constraints:
            s2.add(c)
            
        # Check equivalence
        # Two policies are equivalent if they allow/deny the same actions under the same conditions
        result = s1.check() == s2.check()
        print(f"Solver 1 result: {s1.check()}")
        print(f"Solver 2 result: {s2.check()}")
        return result

def run_test_case(name: str, prompt: str, aws_policy: dict):
    print(f"\nTest Case: {name}")
    print("Prompt policy:", prompt)
    print("AWS policy:", json.dumps(aws_policy, indent=2))
    result = validator.policies_are_equivalent(prompt, aws_policy)
    print("Policies are equivalent:", result)
    return result

# Example usage
validator = PolicyValidator()

# Test Case 1: Matching instance type restrictions
test1_prompt = "ALLOW user:developer RunInstances t2.micro,t2.small"
test1_aws = {
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:instance/*"],
    "Condition": {
        "StringEquals": {
            "ec2:InstanceType": ["t2.micro", "t2.small"]
        }
    }
}
result1 = run_test_case("Matching Instance Types", test1_prompt, test1_aws)

# Test Case 2: Matching volume size limit
test2_prompt = "ALLOW user:developer RunInstances LIMIT VolumeSize 16"
test2_aws = {
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:volume/*"],
    "Condition": {
        "NumericLessThanEquals": {
            "ec2:VolumeSize": "16"
        }
    }
}
result2 = run_test_case("Matching Volume Size", test2_prompt, test2_aws)

# Test Case 3: Mismatched instance types
test3_prompt = "ALLOW user:developer RunInstances t2.micro,t2.small"
test3_aws = {
    "Effect": "Allow",
    "Action": ["ec2:RunInstances"],
    "Resource": ["arn:aws:ec2:*:*:instance/*"],
    "Condition": {
        "StringEquals": {
            "ec2:InstanceType": ["t2.large"]  # Different from prompt
        }
    }
}
result3 = run_test_case("Mismatched Instance Types", test3_prompt, test3_aws)

print("\nSummary of all test cases:")
print(f"Test 1 (Matching Instance Types): {result1}")
print(f"Test 2 (Matching Volume Size): {result2}")
print(f"Test 3 (Mismatched Instance Types): {result3}")