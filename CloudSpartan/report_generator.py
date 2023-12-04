def generate_html_report(all_details, recommendations, remediation_steps):
    """Generate an enhanced HTML report from the provided data."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AWS Config Non-Compliant Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 40px;
                background-color: #f5f5f5;
            }
            h2 {
                color: #333;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
                background-color: #ffffff;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            th, td {
                border: 1px solid #dddddd;
                padding: 12px 15px;
                text-align: left;
            }
            tr:nth-child(even) {
                background-color: #f7f7f7;
            }
            th {
                background-color: #007BFF;
                color: white;
                text-transform: uppercase;
            }
        </style>
    </head>
    <body>
        <h2>AWS Config Non-Compliant Resources</h2>
        <table>
            <thead>
                <tr>
                    <th>Rule</th>
                    <th>Resource ARN</th>
                    <th>Resource Name</th>
                    <th>Resource Type</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
    """

    for rule, details in all_details.items():
        for detail in details:
            resource_id = detail['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            resource_type = detail['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']

            resource_type = resource_type.replace("::", " ")
            resource_type = resource_type.replace("AWS", "")

            resource_arn = resource_id
            resource_name = resource_arn.split(':')[-1].split('/')[-1]
            recommendation = recommendations.get(rule, 'No specific recommendation available.')
            remediations = remediation_steps.get(rule, 'No specific recommendation available.')

            html_content += f"""
            <tr>
                <td>{rule}</td>
                <td>{resource_arn}</td>
                <td>{resource_name}</td>
                <td>{resource_type}</td>
                <td>{recommendation}</td>
                <td>{remediations}</td>
            </tr>
            """

    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """

    with open("aws_config_report.html", "w") as file:
        file.write(html_content)
