import json
import unittest
from unittest.mock import patch, MagicMock
from lambda.slack_alert import lambda_handler, send_slack_notification


class TestSlackAlert(unittest.TestCase):
    def test_lambda_handler_no_findings(self):
        event = {'detail': {'findings': []}}
        result = lambda_handler(event, {})
        self.assertEqual(result['statusCode'], 200)

    def test_slack_notification_no_webhook(self):
        finding = {'Title': 'Test', 'Severity': {'Label': 'HIGH'}, 'Description': 'Test'}
        send_slack_notification(finding)

    @patch('urllib.request.urlopen')
    def test_slack_notification_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        finding = {
            'Title': 'S3 Public Access',
            'Severity': {'Label': 'CRITICAL'},
            'Description': 'S3 bucket is publicly accessible',
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/abc123',
            'Resources': [{'Type': 'AWS::S3::Bucket', 'Id': 'arn:aws:s3:::my-bucket'}],
            'UpdatedAt': '2024-01-15T10:00:00Z'
        }

        send_slack_notification(finding)
        mock_urlopen.assert_called_once()


if __name__ == '__main__':
    unittest.main()
