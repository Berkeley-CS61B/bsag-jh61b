from datetime import datetime, timedelta
import math

from bsag import BaseStepConfig, BaseStepDefinition
from bsag.bsagio import BSAGIO
from bsag.steps.gradescope import RESULTS_KEY, Results


class LatenessPenaltyConfig(BaseStepConfig):
    penalty_per_day: float = 2.0
    grace_period_minutes: int = 30


class LatenessPenalty(BaseStepDefinition[LatenessPenaltyConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.lateness_penalty"

    @classmethod
    def display_name(cls, config: LatenessPenaltyConfig) -> str:
        return "Lateness Penalty"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: LatenessPenaltyConfig) -> bool:
        res: Results = bsagio.data[RESULTS_KEY]
        
        # Get submission info from gradescope
        submission_info = bsagio.data.get("gradescope_submission_metadata", {})
        
        if not submission_info:
            bsagio.private.warning("No submission metadata found - cannot calculate lateness penalty")
            return True
            
        # Extract submission time and due date
        submission_time_str = submission_info.get("created_at")
        due_date_str = submission_info.get("assignment", {}).get("due_date")
        
        if not submission_time_str or not due_date_str:
            bsagio.private.warning("Missing submission time or due date - cannot calculate lateness penalty")
            return True
            
        try:
            # Parse timestamps (assuming ISO format)
            submission_time = datetime.fromisoformat(submission_time_str.replace('Z', '+00:00'))
            due_date = datetime.fromisoformat(due_date_str.replace('Z', '+00:00'))
            
            # Calculate lateness
            time_diff = submission_time - due_date
            
            if time_diff <= timedelta(0):
                # Submitted on time
                bsagio.student.info("Submitted on time - no lateness penalty")
                return True
                
            # Apply grace period
            grace_period = timedelta(minutes=config.grace_period_minutes)
            if time_diff <= grace_period:
                bsagio.student.info(f"Submitted within {config.grace_period_minutes}-minute grace period - no penalty")
                return True
                
            # Calculate penalty
            late_minutes = (time_diff - grace_period).total_seconds() / 60
            days_late = math.ceil(late_minutes / (24 * 60))  # Round up to full days
            penalty = days_late * config.penalty_per_day
            
            # Apply penalty
            res.score = max(0, res.score - penalty)
            
            bsagio.student.info(f"Assignment submitted {days_late} day(s) late")
            bsagio.student.info(f"Lateness penalty: -{penalty} points ({config.penalty_per_day} points per day)")
            bsagio.private.info(f"Applied lateness penalty: -{penalty} points for {days_late} days late")
            
        except Exception as e:
            bsagio.private.error(f"Error calculating lateness penalty: {e}")
            return True  # Don't fail the grading if penalty calculation fails
            
        return True