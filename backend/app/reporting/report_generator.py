import json
import csv
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from app.utils.logger import logger

class ReportGenerator:
    """
    ReportGenerator generates reports from scan results in various formats.
    
    Supported report formats are JSON, CSV, and PDF. The class uses the scan results
    provided during initialization to produce formatted reports with remediation details,
    risk scores, and other relevant information.
    """

    def __init__(self, scan_results):
        """
        Initializes the report generator with the provided scan results.

        Args:
            scan_results (dict): A dictionary containing the results of all scans.
        """
        self.scan_results = scan_results

    def generate_report(self, format="json"):
        """
        Generates a report in the specified format.

        Supported formats:
          - json: Returns the scan results as a JSON-like dictionary.
          - csv: Returns a dictionary mapping service names to CSV formatted strings.
          - pdf: Returns the PDF report as binary data.
        
        Args:
            format (str): The desired output format ('json', 'csv', 'pdf'). Defaults to 'json'.

        Returns:
            The generated report in the requested format.

        Raises:
            ValueError: If the format is unsupported.
            Exception: Re-raises any exception encountered during report generation.
        """
        try:
            format = format.lower()
            if format == "json":
                return self._generate_json_report()
            elif format == "csv":
                return self._generate_csv_report()
            elif format == "pdf":
                return self._generate_pdf_report()
            else:
                raise ValueError("Unsupported format. Supported formats: json, csv, pdf.")
        except Exception as e:
            logger.exception("Error generating report:")
            raise

    def _generate_json_report(self):
        """
        Generates a JSON report by returning the scan results as-is.

        Returns:
            dict: The scan results dictionary.
        """
        logger.info("Generating JSON report.")
        return self.scan_results

    def _generate_csv_report(self):
        """
        Generates a CSV report for each service.

        It iterates over the scan results by service. For each service, it flattens the results 
        into rows and writes them as CSV using Python's csv.DictWriter, then returns a dictionary 
        mapping each service name to its CSV string output.

        Returns:
            dict: A dictionary where keys are service names and values are CSV formatted strings.
        """
        logger.info("Generating CSV report.")
        output = {}
        # Iterate over each service in the scan results
        for service, results in self.scan_results.items():
            rows = []
            # If the results are organized in categories, flatten them into rows.
            if isinstance(results, dict):
                for category, items in results.items():
                    for item in items:
                        row = {"Service": service, "Category": category}
                        row.update(item)
                        rows.append(row)
            else:
                rows = results
            
            # Generate CSV if there are rows present.
            if rows:
                si = io.StringIO()
                fieldnames = list(rows[0].keys())
                writer = csv.DictWriter(si, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
                output[service] = si.getvalue()
            else:
                output[service] = ""
        logger.info("CSV report generation complete.")
        return output

    def _generate_pdf_report(self):
        """
        Generates a PDF report using ReportLab.

        The PDF includes a header and iterates over the scan results, writing the service and its details
        with some basic formatting. If the content overflows the page, a new page is added.

        Returns:
            bytes: The binary content of the generated PDF.
        """
        logger.info("Generating PDF report.")
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        # Draw report header
        p.setFont("Helvetica-Bold", 16)
        p.drawString(72, height - 72, "Cloud Service Misconfiguration Scanner Report")

        p.setFont("Helvetica", 12)
        y = height - 100

        # Iterate over each service and its details in the scan results.
        for service, details in self.scan_results.items():
            p.drawString(72, y, f"Service: {service}")
            y -= 20
            if isinstance(details, dict):
                for category, items in details.items():
                    p.drawString(90, y, f"{category}:")
                    y -= 15
                    for item in items:
                        # Concatenate key-value pairs into a single line.
                        line = ", ".join([f"{k}: {v}" for k, v in item.items()])
                        p.drawString(110, y, line)
                        y -= 15
                        # Add a new page if the content reaches near the bottom.
                        if y < 72:
                            p.showPage()
                            y = height - 72
            else:
                p.drawString(90, y, str(details))
                y -= 15
            y -= 10
            if y < 72:
                p.showPage()
                y = height - 72

        p.showPage()
        p.save()
        buffer.seek(0)
        logger.info("PDF report generation complete.")
        return buffer.read()
