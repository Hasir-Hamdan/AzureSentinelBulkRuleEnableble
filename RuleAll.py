import json
import argparse
import requests
from azure.identity import DefaultAzureCredential


def connect_to_azure(subscription_id, resource_group_name, workspace_name, solution_name, enable_rules):
    try:
        credential = DefaultAzureCredential()
        api_version = "2024-01-01-preview"
        token = credential.get_token("https://management.azure.com/.default").token

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        print("\n[+] Fetching content packages...")
        content_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentProductPackages?api-version={api_version}"
        content_response = requests.get(content_uri, headers=headers)

        if content_response.status_code == 404:
            print(f"[-] URL not found: {content_uri}")
            return

        content_response.raise_for_status()

        solutions = [s for s in content_response.json().get('value', []) if s.get('properties', {}).get('version')]
        solution = next((s for s in solutions if s['properties']['displayName'] == solution_name), None)

        if not solution:
            raise Exception(f"[-] Solution Name: [{solution_name}] not found. Ensure it is installed in Content Hub")

        print(f"[+] Solution '{solution_name}' found. Getting templates...")

        content_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentTemplates?api-version={api_version}"
        content_response = requests.get(content_uri, headers=headers)

        if content_response.status_code == 404:
            print(f"[-] URL not found: {content_uri}")
            return

        content_response.raise_for_status()

        content_templates = [t for t in content_response.json().get('value', []) if
                             t.get('properties', {}).get('packageId') == solution['properties']['contentId'] and t.get('properties', {}).get('contentKind') == 'AnalyticsRule']

        print(f"[+] {len(content_templates)} Analytic Rules found for: '{solution_name}'")

        for content_template in content_templates:
            rule_name = content_template['name']
            rule_template_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentTemplates/{rule_name}?api-version={api_version}"
            rule_response = requests.get(rule_template_uri, headers=headers)
            rule_response.raise_for_status()

            rule_properties = next((r['properties'] for r in rule_response.json().get('properties', {}).get('mainTemplate', {}).get('resources', []) if r.get('type') == 'Microsoft.OperationalInsights/workspaces/providers/metadata'), None)
            if rule_properties:
                rule_properties.pop('description', None)
                rule_properties.pop('parentId', None)

            rule = next((r for r in rule_response.json().get('properties', {}).get('mainTemplate', {}).get('resources', []) if r.get('type') == 'Microsoft.SecurityInsights/AlertRuleTemplates'), None)
            if rule:
                rule['properties']['alertRuleTemplateName'] = rule['name']
                rule['properties']['templateVersion'] = rule_response.json().get('properties', {}).get('version')
                rule['properties']['enabled'] = enable_rules

            rule_payload = json.dumps(rule, separators=(',', ':'))
            rule_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules/{rule['name']}?api-version={api_version}"

            rule_result = requests.put(rule_uri, headers=headers, data=rule_payload)
            if rule_result.status_code in [200, 201]:
                print(f"[+] {'Enabled' if enable_rules else 'Created'} rule: {rule['properties']['displayName']}")
            else:
                print(f"[-] Failed to create/enable rule: {rule['properties']['displayName']} => {rule_result.text}")
                continue

            rule_result = rule_result.json()
            rule_properties['parentId'] = rule_result['id']

            metadata_payload = json.dumps({"properties": rule_properties}, separators=(',', ':'))
            metadata_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/metadata/analyticsrule-{rule['name']}?api-version={api_version}"
            metadata_response = requests.put(metadata_uri, headers=headers, data=metadata_payload)

            if metadata_response.status_code in [200, 201]:
                print(f"[+] Metadata updated for: {rule['properties']['displayName']}")
            else:
                print(f"[-] Failed to update metadata for: {rule['properties']['displayName']} => {metadata_response.text}")

    except Exception as e:
        print(f"[!] Error: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enable Sentinel Analytics Rules in Bulk")
    parser.add_argument("-sub", "--subscription_id", required=True, help="Azure Subscription ID")
    parser.add_argument("-rg", "--resource_group", required=True, help="Resource Group Name")
    parser.add_argument("-ws", "--workspace", required=True, help="Log Analytics Workspace Name")
    parser.add_argument("-sn", "--solution_name", required=True, help="Name of the Content Hub Solution")
    parser.add_argument("-e", "--enable", action="store_true", help="Enable the rules (default is just create)")

    args = parser.parse_args()

    connect_to_azure(
        subscription_id=args.subscription_id,
        resource_group_name=args.resource_group,
        workspace_name=args.workspace,
        solution_name=args.solution_name,
        enable_rules=args.enable
    )
