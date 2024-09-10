import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAILS

def send_email(subject, message):
    try:
        # Add a timeout of 10 seconds
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECIPIENT_EMAILS)
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'html'))

        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print("Error sending email:", str(e))

def notify_script_start(protection_level, allowed_mariadb_ips, allowed_ports):
    subject = "DDoS Protection Script Started"
    message = f"""
    <html>
    <body>
    <h2>Dear Admin,</h2>
    <p>Block DDoS protection script has started successfully on the server:</p>
    <ul>
        <li><strong>Protection Level:</strong> {protection_level}</li>
        <li><strong>Allowed MariaDB IPs:</strong> {', '.join(allowed_mariadb_ips)}</li>
        <li><strong>Allowed Ports:</strong> {', '.join(allowed_ports)}</li>
    </ul>
    <p>Best regards,<br>Block DDoS System</p>
    </body>
    </html>
    """
    send_email(subject, message)

def notify_ddos_activity(activity_details):
    subject = "DDoS Activity Detected on Your Server"
    message = f"""
    <html>
    <body>
    <h2>Dear Admin,</h2>
    <p>We detected a potential DDoS attack on your server:</p>
    <p><strong>{activity_details}</strong></p>
    <p>Best regards,<br>Block DDoS Security System</p>
    </body>
    </html>
    """
    send_email(subject, message)

def notify_level_change(old_level, new_level):
    subject = "Protection Level Changed on Your Server"
    message = f"""
    <html>
    <body>
    <h2>Dear Admin,</h2>
    <p>The protection level on your server has changed:</p>
    <p><strong>Old Level: {old_level}</strong></p>
    <p><strong>New Level: {new_level}</strong></p>
    <p>Best regards,<br>Block DDoS Security System</p>
    </body>
    </html>
    """
    send_email(subject, message)
