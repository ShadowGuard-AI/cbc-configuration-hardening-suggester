import argparse
import logging
import re
import yaml
import json
import jsonschema
from jsonschema import SchemaError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes system configuration and suggests hardening measures.")
    parser.add_argument("config_file", help="Path to the system configuration file (YAML).")
    parser.add_argument("baseline_file", help="Path to the security baseline file (JSON Schema).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def load_config(config_file):
    """
    Loads the system configuration from a YAML file.
    Handles file not found and YAML parsing errors.
    """
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        return config_data
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise

def load_baseline(baseline_file):
    """
    Loads the security baseline from a JSON Schema file.
    Handles file not found and JSON parsing errors.
    """
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
        return baseline_data
    except FileNotFoundError:
        logging.error(f"Baseline file not found: {baseline_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        raise

def validate_config(config_data, baseline_data):
    """
    Validates the configuration data against the JSON Schema baseline.
    Returns a list of validation errors, empty when the config is valid.
    Raises SchemaError when the baseline itself is not a valid schema.
    """
    validator_cls = jsonschema.validators.validator_for(baseline_data)
    validator_cls.check_schema(baseline_data)
    validator = validator_cls(baseline_data)
    # Sort by path so the report order is stable from run to run.
    return sorted(
        validator.iter_errors(config_data),
        key=lambda e: [str(part) for part in e.path],
    )

def error_path(error):
    """
    Returns the property path a validation error belongs to, as a list.
    A 'required' error is reported at the parent object, so the missing
    property named in its message is appended: that missing property is
    the path the report item, and the baseline lookup, are about.
    """
    path = [str(part) for part in error.path]
    if error.validator == "required":
        # This depends on the exact wording of the library's message.
        # A jsonschema version that phrases it differently leaves the
        # path at the parent, and the report item then names the
        # object instead of the missing property.
        match = re.match(r"'([^']+)' is a required property", error.message)
        if match:
            path.append(match.group(1))
    return path

def generate_report(validation_errors, baseline_data):
     """
     Builds the non-compliance report from the validation errors: one
     item per error, at that error's path, carrying the error message.
     Recommendation and severity come from the baseline at that path
     where the baseline carries them, and fall back to the defaults in
     find_recommendation and find_severity where it carries nothing.
     """
     report = []
     for error in validation_errors:
        item_path = error_path(error)
        report.append({
            "property": ".".join(item_path) if item_path else "root",
            "message": error.message,
            "recommendation": find_recommendation(baseline_data, item_path),
            "severity": find_severity(baseline_data, item_path)
        })
     return report

def find_recommendation(baseline_data, item_path):
    """
    Finds the remediation recommendation in the baseline data for a given property path.
    """
    # The walk goes through properties and nothing else. A baseline
    # that nests through items, patternProperties, or a composed
    # schema is never followed, so its recommendations are invisible
    # here and the default text below is what the report shows. The
    # severity lookup further down shares this limit and its own
    # default, Medium, which is an invented severity for any property
    # whose baseline entry carries none.
    current = baseline_data
    try:
        for part in item_path:
            current = current['properties'][part]
        if 'recommendation' in current:
            return current['recommendation']
        else:
             return "No specific recommendation available."
    except (KeyError, TypeError):
        return "No specific recommendation available."

def find_severity(baseline_data, item_path):
    """
    Finds the severity of the configuration item in the baseline data.
    """
    current = baseline_data
    try:
        for part in item_path:
            current = current['properties'][part]

        if 'severity' in current:
            return current['severity']
        else:
            return "Medium"
    except (KeyError, TypeError):
        return "Medium"

def print_report(report):
    """
    Prints the non-compliance report to the console.
    """
    if report:
        print("Non-Compliance Report:")
        for item in report:
            print(f"  Property: {item['property']}")
            print(f"    Message: {item['message']}")
            print(f"    Recommendation: {item['recommendation']}")
            print(f"    Severity: {item['severity']}")
            print("-" * 30)
    else:
        print("No non-compliance issues found.")

def main():
    """
    Main function to orchestrate the configuration analysis and reporting.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load configuration and baseline
        config_data = load_config(args.config_file)
        baseline_data = load_baseline(args.baseline_file)

        # Validate configuration against baseline. The validation
        # errors are the report: a failed validation prints one item
        # per error and exits nonzero, and the no issues line is
        # printed only when validation passes.
        validation_errors = validate_config(config_data, baseline_data)

        report = generate_report(validation_errors, baseline_data)
        print_report(report)

        if validation_errors:
            logging.error("Configuration does not conform to the baseline.")
            exit(1)

    except SchemaError as e:
        logging.error(f"Schema error: {e.message}")
        exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)

if __name__ == "__main__":
     # Example Usage (replace with actual file paths):
    # Create sample YAML config file (config.yaml)
    # with open("config.yaml", "w") as f:
    #     f.write("""
    # server:
    #     hostname: example.com
    #     port: 8080
    #     security:
    #         ssl_enabled: false
    #         tls_version: "1.2"
    # """)

    # Create sample JSON Schema baseline (baseline.json)
    # with open("baseline.json", "w") as f:
    #     f.write("""
    # {
    #     "$schema": "http://json-schema.org/draft-07/schema#",
    #     "title": "Security Baseline",
    #     "type": "object",
    #     "properties": {
    #         "server": {
    #             "type": "object",
    #             "properties": {
    #                 "hostname": {
    #                     "type": "string"
    #                 },
    #                 "port": {
    #                     "type": "integer"
    #                 },
    #                 "security": {
    #                     "type": "object",
    #                     "properties": {
    #                         "ssl_enabled": {
    #                             "type": "boolean",
    #                             "recommendation": "Enable SSL to encrypt traffic.",
    #                             "severity": "High"
    #                         },
    #                         "tls_version": {
    #                             "type": "string",
    #                             "enum": ["1.3", "1.2"],
    #                             "recommendation": "Use TLS version 1.3 for enhanced security.",
    #                             "severity": "Medium"
    #                         }
    #                     },
    #                     "required": ["ssl_enabled", "tls_version"]
    #                 }
    #             },
    #             "required": ["hostname", "port", "security"]
    #         }
    #     },
    #     "required": ["server"]
    # }
    # """)

    #  To run:
    #  python main.py config.yaml baseline.json
    main()