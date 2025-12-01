#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vulnerability command implementation for managing vulnerabilities in the database
"""

import argparse
import json
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table

class VulnCommand(BaseCommand):
    """Command to manage vulnerabilities in the database"""
    
    @property
    def name(self) -> str:
        return "vuln"
    
    @property
    def description(self) -> str:
        return "Manage vulnerabilities in the database"
    
    @property
    def usage(self) -> str:
        return "vulns [--add] [--list] [--delete] [--info] [--search] [--update] [--import] [--export]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage vulnerabilities in the database, similar to Metasploit's
vulns command. You can add, list, delete, search, and update vulnerability information.

Options:
    --add, -a              Add a new vulnerability
    --list, -l             List all vulnerabilities
    --delete, -d <id>      Delete a vulnerability by ID
    --info, -i <id>        Show detailed information about a vulnerability
    --search, -s <term>    Search vulnerabilities by name, CVE, or description
    --update, -u <id>      Update vulnerability information
    --import <file>        Import vulnerabilities from JSON file
    --export <file>        Export vulnerabilities to JSON file
    --host <id>            Show vulnerabilities for specific host
    --risk_level <level>     Filter by risk_level (critical, high, medium, low, info)
    --limit <num>          Limit number of results (default: 50)
    --json                 Output in JSON format

Examples:
    vulns --add --name "CVE-2021-44228" --host 1 --risk_level critical
    vulns --list                                          # List all vulnerabilities
    vulns --search "CVE-2021"                            # Search for CVE-2021 vulnerabilities
    vulns --info 1                                        # Show info for vulnerability ID 1
    vulns --delete 1                                      # Delete vulnerability ID 1
    vulns --host 1                                        # Show vulnerabilities for host ID 1
    vulns --risk_level critical                             # Show only critical vulnerabilities
    vulns --export vulns.json                             # Export all vulnerabilities
    vulns --import vulns.json                             # Import vulnerabilities from file
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Manage vulnerabilities in the database",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  vulns --add --name "CVE-2021-44228" --host 1 --risk_level critical
  vulns --list                                          # List all vulnerabilities
  vulns --search "CVE-2021"                            # Search for CVE-2021 vulnerabilities
  vulns --info 1                                        # Show info for vulnerability ID 1
  vulns --delete 1                                      # Delete vulnerability ID 1
  vulns --host 1                                        # Show vulnerabilities for host ID 1
  vulns --risk_level critical                             # Show only critical vulnerabilities
  vulns --export vulns.json                             # Export all vulnerabilities
  vulns --import vulns.json                             # Import vulnerabilities from file
            """
        )
        
        # Action arguments
        parser.add_argument("--add", "-a", action="store_true", help="Add a new vulnerability")
        parser.add_argument("--list", "-l", action="store_true", help="List all vulnerabilities")
        parser.add_argument("--delete", "-d", dest="delete_id", type=int, help="Delete vulnerability by ID")
        parser.add_argument("--info", "-i", dest="info_id", type=int, help="Show detailed vulnerability information")
        parser.add_argument("--search", "-s", dest="search_term", help="Search vulnerabilities")
        parser.add_argument("--update", "-u", dest="update_id", type=int, help="Update vulnerability information")
        parser.add_argument("--import", dest="import_file", help="Import vulnerabilities from JSON file")
        parser.add_argument("--export", dest="export_file", help="Export vulnerabilities to JSON file")
        
        # Filter arguments
        parser.add_argument("--host", type=int, help="Show vulnerabilities for specific host ID")
        parser.add_argument("--risk_level", choices=["critical", "high", "medium", "low", "info"], 
                          help="Filter by risk_level level")
        parser.add_argument("--limit", type=int, default=50, help="Limit number of results")
        parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        # Add vulnerability arguments
        parser.add_argument("--name", help="Vulnerability name (for --add)")
        parser.add_argument("--description", help="Vulnerability description (for --add)")
        parser.add_argument("--cve", help="CVE identifier (for --add)")
        parser.add_argument("--cvss", type=float, help="CVSS score (for --add)")
        parser.add_argument("--references", help="References (JSON array for --add)")
        parser.add_argument("--solution", help="Solution/remediation (for --add)")
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the vulns command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        try:
            # Get database session
            if not hasattr(self.framework, 'get_db_session'):
                print_error("Database not available")
                return False
            
            session = self.framework.get_db_session()
            
            if parsed_args.add:
                return self._add_vulnerability(session, parsed_args)
            elif parsed_args.list:
                return self._list_vulnerabilities(session, parsed_args)
            elif parsed_args.delete_id:
                return self._delete_vulnerability(session, parsed_args.delete_id)
            elif parsed_args.info_id:
                return self._show_vulnerability_info(session, parsed_args.info_id)
            elif parsed_args.search_term:
                return self._search_vulnerabilities(session, parsed_args)
            elif parsed_args.update_id:
                return self._update_vulnerability(session, parsed_args.update_id)
            elif parsed_args.import_file:
                return self._import_vulnerabilities(session, parsed_args.import_file)
            elif parsed_args.export_file:
                return self._export_vulnerabilities(session, parsed_args.export_file)
            elif parsed_args.host:
                return self._show_host_vulnerabilities(session, parsed_args.host, parsed_args)
            else:
                # Default: list vulnerabilities
                return self._list_vulnerabilities(session, parsed_args)
                    
        except Exception as e:
            print_error(f"Error executing vulns command: {str(e)}")
            return False
    
    def _add_vulnerability(self, session, parsed_args):
        """Add a new vulnerability to the database"""
        try:
            from core.models.models import Vulnerability, Host, Workspace
            
            # Validate required fields
            if not parsed_args.name:
                print_error("Vulnerability name is required (--name)")
                return False
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Host is optional for now
            # if parsed_args.host:
            #     host = session.query(Host).filter(
            #         Host.id == parsed_args.host,
            #         Host.workspace_id == workspace.id
            #     ).first()
            #     if not host:
            #         print_error(f"Host with ID {parsed_args.host} not found")
            #         return False
            
            # Determine risk_level
            risk_level = parsed_args.risk_level or "medium"
            if parsed_args.cvss:
                if parsed_args.cvss >= 9.0:
                    risk_level = "critical"
                elif parsed_args.cvss >= 7.0:
                    risk_level = "high"
                elif parsed_args.cvss >= 4.0:
                    risk_level = "medium"
                elif parsed_args.cvss >= 0.1:
                    risk_level = "low"
                else:
                    risk_level = "info"
            
            # Create new vulnerability
            new_vuln = Vulnerability(
                name=parsed_args.name,
                description=parsed_args.description or "",
                cve=parsed_args.cve or "",
                risk_level=risk_level,
                cvss_score=str(parsed_args.cvss) if parsed_args.cvss else "",
                proof_of_concept=parsed_args.references or "",
                remediation=parsed_args.solution or ""
            )
            
            session.add(new_vuln)
            session.commit()
            
            print_success(f"Added vulnerability '{parsed_args.name}' (ID: {new_vuln.id})")
            return True
            
        except Exception as e:
            print_error(f"Error adding vulnerability: {str(e)}")
            return False
    
    def _list_vulnerabilities(self, session, parsed_args):
        """List vulnerabilities in the database"""
        try:
            from core.models.models import Vulnerability, Host, Workspace
            from sqlalchemy import and_
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Build query
            query = session.query(Vulnerability)
            
            # Apply filters
            if parsed_args.risk_level:
                query = query.filter(Vulnerability.risk_level == parsed_args.risk_level)
            
            vulnerabilities = query.limit(parsed_args.limit).all()
            
            if not vulnerabilities:
                print_info("No vulnerabilities found in database")
                return True
            
            if parsed_args.json:
                # JSON output
                vulns_data = []
                for vuln in vulnerabilities:
                    vulns_data.append({
                        'id': vuln.id,
                        'name': vuln.name,
                        'cve': vuln.cve,
                        'risk_level': vuln.risk_level,
                        'cvss_score': vuln.cvss_score,
                        'id': vuln.id,
                        'created_at': vuln.created_at.isoformat() if vuln.created_at else None
                    })
                print(json.dumps(vulns_data, indent=2))
            else:
                # Table output
                headers = ["ID", "Name", "CVE", "Severity", "CVSS", "Host ID", "Status", "Discovered"]
                rows = []
                
                for vuln in vulnerabilities:
                    discovered = vuln.created_at.strftime("%Y-%m-%d") if vuln.created_at else "Unknown"
                    cvss_str = f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
                    
                    rows.append([
                        str(vuln.id),
                        vuln.name[:30] + "..." if len(vuln.name) > 30 else vuln.name,
                        vuln.cve or "N/A",
                        vuln.risk_level.upper(),
                        cvss_str,
                        str(vuln.id),
                        vuln.risk_level,
                        discovered
                    ])
                
                print_table(headers, rows)
                print_info(f"Found {len(vulnerabilities)} vulnerabilities")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing vulnerabilities: {str(e)}")
            return False
    
    def _delete_vulnerability(self, session, vuln_id):
        """Delete a vulnerability from the database"""
        try:
            from core.models.models import Vulnerability
            
            vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if not vuln:
                print_error(f"Vulnerability with ID {vuln_id} not found")
                return False
            
            session.delete(vuln)
            session.commit()
            
            print_success(f"Deleted vulnerability '{vuln.name}' (ID: {vuln_id})")
            return True
            
        except Exception as e:
            print_error(f"Error deleting vulnerability: {str(e)}")
            return False
    
    def _show_vulnerability_info(self, session, vuln_id):
        """Show detailed information about a vulnerability"""
        try:
            from core.models.models import Vulnerability, Host
            
            vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if not vuln:
                print_error(f"Vulnerability with ID {vuln_id} not found")
                return False
            
            # Get host information
            host = session.query(Host).filter(Host.id == vuln.id).first()
            
            print_info(f"Vulnerability Information - ID: {vuln_id}")
            print_info("=" * 60)
            print_info(f"Name: {vuln.name}")
            print_info(f"CVE: {vuln.cve or 'N/A'}")
            print_info(f"Severity: {vuln.risk_level.upper()}")
            print_info(f"CVSS Score: {vuln.cvss_score if vuln.cvss_score else 'N/A'}")
            print_info(f"Status: {vuln.risk_level}")
            print_info(f"Host: {host.ip_address if host else 'Unknown'} (ID: {vuln.id})")
            print_info(f"Discovered: {vuln.created_at.strftime('%Y-%m-%d %H:%M:%S') if vuln.created_at else 'Unknown'}")
            
            if vuln.description:
                print_info(f"\nDescription:")
                print_info(f"{vuln.description}")
            
            if vuln.references:
                print_info(f"\nReferences:")
                try:
                    refs = json.loads(vuln.references) if vuln.references.startswith('[') else [vuln.references]
                    for ref in refs:
                        print_info(f"  - {ref}")
                except:
                    print_info(f"  - {vuln.references}")
            
            if vuln.solution:
                print_info(f"\nSolution:")
                print_info(f"{vuln.solution}")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing vulnerability info: {str(e)}")
            return False
    
    def _search_vulnerabilities(self, session, parsed_args):
        """Search vulnerabilities by various criteria"""
        try:
            from core.models.models import Vulnerability, Workspace
            from sqlalchemy import or_
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Build search query
            search_term = parsed_args.search_term.lower()
            query = session.query(Vulnerability).filter(
                Vulnerability.service_id == workspace.id,
                or_(
                    Vulnerability.name.contains(search_term),
                    Vulnerability.cve.contains(search_term),
                    Vulnerability.description.contains(search_term)
                )
            )
            
            # Apply additional filters
            if parsed_args.host:
                query = query.filter(Vulnerability.id == parsed_args.host)
            
            if parsed_args.risk_level:
                query = query.filter(Vulnerability.risk_level == parsed_args.risk_level)
            
            vulnerabilities = query.limit(parsed_args.limit).all()
            
            if not vulnerabilities:
                print_info(f"No vulnerabilities found matching '{parsed_args.search_term}'")
                return True
            
            if parsed_args.json:
                # JSON output
                vulns_data = []
                for vuln in vulnerabilities:
                    vulns_data.append({
                        'id': vuln.id,
                        'name': vuln.name,
                        'cve': vuln.cve,
                        'risk_level': vuln.risk_level,
                        'cvss_score': vuln.cvss_score,
                        'id': vuln.id,
                        'created_at': vuln.created_at.isoformat() if vuln.created_at else None
                    })
                print(json.dumps(vulns_data, indent=2))
            else:
                # Table output
                headers = ["ID", "Name", "CVE", "Severity", "CVSS", "Host ID", "Status", "Discovered"]
                rows = []
                
                for vuln in vulnerabilities:
                    discovered = vuln.created_at.strftime("%Y-%m-%d") if vuln.created_at else "Unknown"
                    cvss_str = f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
                    
                    rows.append([
                        str(vuln.id),
                        vuln.name[:30] + "..." if len(vuln.name) > 30 else vuln.name,
                        vuln.cve or "N/A",
                        vuln.risk_level.upper(),
                        cvss_str,
                        str(vuln.id),
                        vuln.risk_level,
                        discovered
                    ])
                
                print_table(headers, rows)
                print_info(f"Found {len(vulnerabilities)} vulnerabilities matching '{parsed_args.search_term}'")
            
            return True
            
        except Exception as e:
            print_error(f"Error searching vulnerabilities: {str(e)}")
            return False
    
    def _update_vulnerability(self, session, vuln_id):
        """Update vulnerability information (interactive)"""
        try:
            from core.models.models import Vulnerability
            
            vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if not vuln:
                print_error(f"Vulnerability with ID {vuln_id} not found")
                return False
            
            print_info(f"Updating vulnerability '{vuln.name}' (ID: {vuln_id})")
            print_info("Press Enter to keep current value")
            
            # Update name
            new_name = input(f"Name [{vuln.name}]: ").strip()
            if new_name:
                vuln.name = new_name
            
            # Update CVE
            new_cve = input(f"CVE [{vuln.cve or ''}]: ").strip()
            if new_cve:
                vuln.cve = new_cve
            
            # Update risk_level
            new_risk_level = input(f"Severity [{vuln.risk_level}]: ").strip()
            if new_risk_level and new_risk_level in ["critical", "high", "medium", "low", "info"]:
                vuln.risk_level = new_risk_level
            
            # Update CVSS score
            new_cvss = input(f"CVSS Score [{vuln.cvss_score or ''}]: ").strip()
            if new_cvss:
                try:
                    vuln.cvss_score = float(new_cvss)
                except ValueError:
                    print_warning("Invalid CVSS score, keeping current value")
            
            # Update risk_level
            new_risk_level = input(f"Status [{vuln.risk_level}]: ").strip()
            if new_risk_level:
                vuln.risk_level = new_risk_level
            
            # Update description
            new_desc = input(f"Description [{vuln.description or ''}]: ").strip()
            if new_desc:
                vuln.description = new_desc
            
            session.commit()
            print_success(f"Updated vulnerability '{vuln.name}'")
            return True
            
        except Exception as e:
            print_error(f"Error updating vulnerability: {str(e)}")
            return False
    
    def _show_host_vulnerabilities(self, session, id, parsed_args):
        """Show vulnerabilities for a specific host"""
        try:
            from core.models.models import Host, Vulnerability, Workspace
            
            # Check if host exists
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            host = session.query(Host).filter(
                Host.id == id,
                Host.service_id == workspace.id
            ).first()
            if not host:
                print_error(f"Host with ID {id} not found")
                return False
            
            # Get vulnerabilities for this host
            query = session.query(Vulnerability).filter(Vulnerability.id == id)
            
            if parsed_args.risk_level:
                query = query.filter(Vulnerability.risk_level == parsed_args.risk_level)
            
            vulnerabilities = query.limit(parsed_args.limit).all()
            
            if not vulnerabilities:
                print_info(f"No vulnerabilities found for host {host.ip_address} (ID: {id})")
                return True
            
            print_info(f"Vulnerabilities for {host.ip_address} (ID: {id})")
            print_info("=" * 50)
            
            if parsed_args.json:
                # JSON output
                vulns_data = []
                for vuln in vulnerabilities:
                    vulns_data.append({
                        'id': vuln.id,
                        'name': vuln.name,
                        'cve': vuln.cve,
                        'risk_level': vuln.risk_level,
                        'cvss_score': vuln.cvss_score,
                        'risk_level': vuln.risk_level,
                        'created_at': vuln.created_at.isoformat() if vuln.created_at else None
                    })
                print(json.dumps(vulns_data, indent=2))
            else:
                # Table output
                headers = ["ID", "Name", "CVE", "Severity", "CVSS", "Status", "Discovered"]
                rows = []
                
                for vuln in vulnerabilities:
                    discovered = vuln.created_at.strftime("%Y-%m-%d") if vuln.created_at else "Unknown"
                    cvss_str = f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
                    
                    rows.append([
                        str(vuln.id),
                        vuln.name[:30] + "..." if len(vuln.name) > 30 else vuln.name,
                        vuln.cve or "N/A",
                        vuln.risk_level.upper(),
                        cvss_str,
                        vuln.risk_level,
                        discovered
                    ])
                
                print_table(headers, rows)
                print_info(f"Found {len(vulnerabilities)} vulnerabilities for host {host.ip_address}")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing host vulnerabilities: {str(e)}")
            return False
    
    def _import_vulnerabilities(self, session, filename):
        """Import vulnerabilities from JSON file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                vulns_data = json.load(f)
            
            imported_count = 0
            for vuln_data in vulns_data:
                if self._add_vulnerability_from_data(session, vuln_data):
                    imported_count += 1
            
            print_success(f"Imported {imported_count} vulnerabilities from {filename}")
            return True
            
        except Exception as e:
            print_error(f"Error importing vulnerabilities: {str(e)}")
            return False
    
    def _export_vulnerabilities(self, session, filename):
        """Export vulnerabilities to JSON file"""
        try:
            from core.models.models import Vulnerability, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Query all vulnerabilities
            vulnerabilities = session.query(Vulnerability).filter(Vulnerability.service_id == workspace.id).all()
            
            # Prepare export data
            vulns_data = []
            for vuln in vulnerabilities:
                vulns_data.append({
                    'id': vuln.id,
                    'name': vuln.name,
                    'cve': vuln.cve,
                    'risk_level': vuln.risk_level,
                    'cvss_score': vuln.cvss_score,
                    'description': vuln.description,
                    'references': vuln.references,
                    'solution': vuln.solution,
                    'created_at': vuln.created_at.isoformat() if vuln.created_at else None
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(vulns_data, f, indent=2, ensure_ascii=False)
            
            print_success(f"Exported {len(vulns_data)} vulnerabilities to {filename}")
            return True
            
        except Exception as e:
            print_error(f"Error exporting vulnerabilities: {str(e)}")
            return False
    
    def _add_vulnerability_from_data(self, session, vuln_data):
        """Add vulnerability from imported data"""
        try:
            from core.models.models import Vulnerability, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                return False
            
            # Check if vulnerability already exists
            existing_vuln = session.query(Vulnerability).filter(
                Vulnerability.service_id == workspace.id,
                Vulnerability.name == vuln_data.get('name'),
                Vulnerability.id == vuln_data.get('id')
            ).first()
            
            if existing_vuln:
                return False  # Skip existing vulnerabilities
            
            # Create new vulnerability
            new_vuln = Vulnerability(
                service_id=workspace.id,
                id=vuln_data.get('id', 0),
                name=vuln_data.get('name', ''),
                description=vuln_data.get('description', ''),
                cve=vuln_data.get('cve', ''),
                risk_level=vuln_data.get('risk_level', 'medium'),
                cvss_score=vuln_data.get('cvss_score', 0.0),
                references=vuln_data.get('references', ''),
                solution=vuln_data.get('solution', '')
            )
            
            session.add(new_vuln)
            session.commit()
            return True
            
        except Exception as e:
            print_error(f"Error adding vulnerability from data: {str(e)}")
            return False
