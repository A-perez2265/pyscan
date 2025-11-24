import argparse
import sys 
import os
import time 
import re 

# Data Structures and Definitions 

class Issue:
    def __init__(self, line, severity, category, description, recommendation):
        self.line = line
        self.severity = severity
        self.category = category
        self.description = description
        self.recommendation = recommendation
    
    def __str__(self, include_details=True):
        if include_details:
            return (
                f"  > Line {self.line}: {self.category} ({self.description})\n"
                f"    Severity: {self.severity}\n"
                f"    Recommendation: {self.recommendation}"
            )
        return f"Line {self.line}: {self.description} ({self.category}, {self.severity})"

# Vulnerability Dictionary: Maps flag to regex patterns and issue details
VULNERABILITY_DICTIONARY = {
    # Risky functions (Code Injection)
    'risky': [
    {
        # eval, exec (Direct code execution)
        'pattern': re.compile(r'\b(eval|exec)\s*\(', re.I),
        'severity': 'HIGH',
        'category': 'Code Injection Risk',
        'description': 'Use of eval() or exec().',
        'recommendation': 'Avoid. Use ast.literal_eval() for safe string evaluation.',
    },
    {
        # os.system, subprocess with shell=True (Command/Shell injection)
        'pattern': re.compile(r'\b(os\.system)\s*\(|\bsubprocess\.(call|run|check_call|check_output).*shell\s*=\s*True', re.I | re.DOTALL),
        'severity': 'HIGH',
        'category': 'Shell Command Injection Risk',
        'description': 'Execution of OS commands via os.system or subprocess with shell=True.',
        'recommendation': 'Use subprocess methods without shell=True, passing arguments as a list.',
    },
    {
        # Insecure Deserialization
        'pattern': re.compile(r'\b(pickle\.(load|loads))', re.I),
        'severity': 'HIGH',
        'category': 'Insecure Deserialization',
        'description': 'Using pickle to deserialize untrusted data.',
        'recommendation': 'Use JSON or another safer serialization format for untrusted data.',
    },
    ],
    # Missing Input Validation
    'validation': [
        {
            # Matches input() or use of sys.argv[index]
            'pattern': re.compile(r'\b(input|raw_input|sys\.argv\[)\s*\[?\(?', re.I), 
            'severity': 'MEDIUM',
            'category': 'Missing Input Validation',
            'description': 'Untrusted input source found.',
            'recommendation': 'Always validate and sanitize user input before processing (e.g., type check, length check, escaping).',
        },
    ],
    # Deprecated Functions
    'deprecated': [
        {
            'pattern': re.compile(r'\b(os\.popen)\s*\(', re.I),
            'severity': 'LOW',
            'category': 'Deprecated/Discouraged Function',
            'description': 'Use of os.popen()',
            'recommendation': 'Use the subprocess module (e.g., subprocess.run) instead.',
        },
    ]
}

# Scanner Logic (Regex) 

class Scanner:
    def scan_file(self, filepath, flags):
        issues_list = []
        enabled_patterns = []
        
        for flag in flags:
            if flag in VULNERABILITY_DICTIONARY:
                enabled_patterns.extend(VULNERABILITY_DICTIONARY[flag])
        
        if not enabled_patterns:
            return issues_list
            
        try:
            # Set to track line numbers that have already triggered a report for a specific category
            vulnerable_lines_per_category = set() 

            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    
                    # Comment/Whitespace Stripping 
                    try:
                        comment_start = line.index('#')
                        # check to see if '#' is outside a string
                        if line[:comment_start].count('"') % 2 == 0 and line[:comment_start].count("'") % 2 == 0:
                            clean_line = line[:comment_start]
                        else:
                            clean_line = line
                    except ValueError:
                        clean_line = line
                        
                    clean_line = clean_line.strip()
                    if not clean_line:
                        continue 
                    
                    
                    # 3. Check the clean line against ALL active patterns
                    for issue_info in enabled_patterns:
                        
                        # We use search() because we only need to confirm existence on the line.
                        if issue_info['pattern'].search(clean_line):
                            
                            issue_category = issue_info['category']
                            
                            # Ensure we don't report the same category/line combination twice.
                            if (line_num, issue_category) not in vulnerable_lines_per_category:
                                
                                issues_list.append(Issue(
                                    line=line_num,
                                    severity=issue_info['severity'],
                                    category=issue_category,
                                    description=issue_info['description'],
                                    recommendation=issue_info['recommendation']
                                ))
                                
                                # Mark the line and category as reported.
                                vulnerable_lines_per_category.add((line_num, issue_category))
                            
            return issues_list
            
        except Exception as e:
            print(f"Error during file analysis: {e}")
            return []


# --- 3. Report Generation ---

class ReportGenerator:
    def __init__(self, filepath, issues, flags):
        self.filepath = filepath
        self.issues = issues
        self.flags = flags
        self.timestamp = time.strftime("%A, %B %d %I:%M%p")

    def format_report(self, format_type):
        if format_type == 'txt':
            return self._format_txt()
        elif format_type == 'pdf': 
            return self._format_pdf()
        return "Invalid format specified."
    
    def _format_txt(self):
        report = []
        report.append(f"{'='*70}")
        report.append(f"STATIC VULNERABILITY SCANNER REPORT")
        report.append(f"{'='*70}\n")
        report.append(f"File Scanned: {self.filepath}")
        report.append(f"Timestamp: {self.timestamp}")
        report.append(f"Flags Enabled: {', '.join(self.flags)}\n")
        report.append(f"Total Issues Found: **{len(self.issues)}**\n")
        
        if self.issues:
            # Grouped report structure
            report.append(f"{'-'*70}")
            report.append("Vulnerability Summary (Validation -> Risky -> Deprecated):")
            report.append(f"{'-'*70}")
            
            # Grouping issues 
            issue_groups = {
                'validation': [i for i in self.issues if 'Validation' in i.category],
                'risky': [i for i in self.issues if 'Injection' in i.category],
                'deprecated': [i for i in self.issues if 'Deprecated' in i.category]
            }

            for group_name, issues in issue_groups.items():
                if issues:
                    report.append(f"\n### {group_name.upper()} Issues Found ({len(issues)}):")
                    for i, issue in enumerate(issues, 1):
                         report.append(f"{i}. {issue}")
        else:
            report.append(f"{'-'*70}")
            report.append("No issues found. Code appears clean!")
            report.append(f"{'-'*70}\n")
            
        return "\n".join(report)

    # Placeholder for PDF generation
    def _format_pdf(self):
        # In a final product, this would generate a PDF file.
        #its not working at the moment 😥
        return self._format_txt().replace('STATIC VULNERABILITY SCANNER REPORT', '--- PDF REPORT GENERATED  ---')

    def save_report(self, report_content, format_type):
        base_name = os.path.splitext(os.path.basename(self.filepath))[0]
        output_filename = f"report_{base_name}.{format_type}"
        try:
            with open(output_filename, 'w') as f:
                f.write(report_content)
            return output_filename
        except IOError as e:
            return f"Error saving file: {e}"

# 4. CLI Class -Main Application Flow 

class CLI:
    def __init__(self):
        self.filepath = None
        self.flags = []
        self.parser = self._create_parser()
        self.scanner = Scanner()
    
    # parser
    def _create_parser(self):
        parser = argparse.ArgumentParser(
            description='Static Vulnerability Scanner for python files',
            epilog='Ex. python main.py yourscript.py'
        )
        parser.add_argument('filepath', help='Path to the python file to scan')
        parser.add_argument('--risky', action='store_true', help='Check for risky functions (eval, exec)')
        parser.add_argument('--validation', action='store_true', help='Check for missing input validation')
        parser.add_argument('--deprecated', action='store_true', help='Check for deprecated functions')
        return parser
    
    def parse_arguments(self, args=None):
        parsed = self.parser.parse_args(args)
        self.filepath = parsed.filepath

        if parsed.risky:
            self.flags.append('risky')
        if parsed.validation:
            self.flags.append('validation')
        if parsed.deprecated:
            self.flags.append('deprecated')

        # Default to all flags if none are provided
        if not self.flags:
            self.flags =['risky', 'validation', 'deprecated']
        
        return self.filepath, self.flags

    def validate_file(self):
        if not os.path.isfile(self.filepath):
            print(f"Error: File not found at path: {self.filepath}")
            return False
        if not self.filepath.lower().endswith('.py'):
            print("Error: File must have a .py extension.")
            return False
        return True
    
    def prompt_for_format(self):
        while True:
            print("\nChoose output format:")
            print("  1. Plain text (.txt)")
            print("  2. PDF (.pdf)") 
            response = input("Enter the number of your choice (1 or 2) and press Enter: ").strip()
            if response == "1":
                return "txt"
            elif response == "2":
                return "pdf"
            else:
                print("Invalid choice. Please enter 1 or 2")

    def run(self):
        try:
            self.parse_arguments()
            
            #Initial Display 
            print(f"\n{'-'*70}")
            print(f"Static Vulnerability Scanner")
            print(f"{'-'*70}\n")
            print(f"Scanning: {self.filepath}")
            print(f"Flags enabled: {', '.join(self.flags)}\n")

            # File Validation 
            if not self.validate_file():
                sys.exit(1)
            
            print("File validation successful.")
            print("Scanning file...")

            # Scanning 
            issues = self.scanner.scan_file(self.filepath, self.flags)
            
            #  Reporting 
            report_gen = ReportGenerator(self.filepath, issues, self.flags)
            
            # Print report to terminal
            print(report_gen._format_txt())

            # Prompt for save format
            format_choice = self.prompt_for_format()
            
            # Generate and save report based on choice
            report_content = report_gen.format_report(format_choice)
            saved_filename = report_gen.save_report(report_content, format_choice)
            
            print(f"\nReport saved to: **{saved_filename}**")
            
            print(f"\n{'-'*70}")
            print("Scan Complete")
            print(f"{'-'*70}\n")

        # Exit on user input and print exception
        except KeyboardInterrupt:
            print("\n\nSession Interrupted by user. Exiting...")
            sys.exit(1)
        except Exception as e:
            if "the following arguments are required: filepath" in str(e):
                 self.parser.print_help()
            print(f"\nError: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    cli = CLI()
    cli.run()