"""Check cumulative reporting across retries without expensive timing samples."""

import contextlib
import io
import unittest
from unittest.mock import patch

from breaks import verify_login


class TimingCountTests(unittest.TestCase):
    def run_attempts(self, validation_results):
        output = io.StringIO()
        # Only sampling is replaced. The retry loop and reporting are exercised.
        with patch.object(verify_login, "recover_secret") as recover, patch.object(
            verify_login.target, "timing_compare", side_effect=validation_results
        ) as oracle, contextlib.redirect_stdout(output):
            recover.side_effect = lambda samples: (b"test", 4 * 256 * samples)
            failure = None
            try:
                verify_login.main()
            except AssertionError as error:
                failure = str(error)
        return output.getvalue(), failure, recover.call_count, oracle.call_count

    def test_first_attempt_stops_and_counts_validation(self):
        output, failure, attempts, validations = self.run_attempts([True])
        self.assertIsNone(failure)
        self.assertEqual((attempts, validations), (1, 1))
        self.assertIn("512000 measurement + 1 validation = 512001", output)

    def test_failed_attempt_is_included_before_success(self):
        output, failure, attempts, validations = self.run_attempts([False, True])
        self.assertIsNone(failure)
        self.assertEqual((attempts, validations), (2, 2))
        self.assertIn("1536000 measurement + 2 validation = 1536002", output)

    def test_success_on_last_attempt_reports_full_worst_case(self):
        output, failure, attempts, validations = self.run_attempts(
            [False, False, False, True]
        )
        self.assertIsNone(failure)
        self.assertEqual((attempts, validations), (4, 4))
        self.assertIn("7680000 measurement + 4 validation = 7680004", output)

    def test_exhaustion_reports_full_worst_case(self):
        output, failure, attempts, validations = self.run_attempts([False] * 4)
        self.assertEqual((attempts, validations), (4, 4))
        self.assertIsNotNone(failure)
        self.assertIn("7680000 measurement + 4 validation = 7680004", failure)
        self.assertNotIn("recovered secret:", output)


if __name__ == "__main__":
    unittest.main()
