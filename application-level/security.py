from db import get_connection


LEVELS = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    "SECRET": 2,
    "TOP_SECRET": 3
}


def evaluate_access(
    role_name,
    logged_in_emp_id,
    target_emp_id,
    table_name,
    column_name
):

    conn = get_connection()

    try:
        with conn.cursor() as cur:

            # =================================================
            # Get role clearance
            # =================================================

            cur.execute("""
                SELECT clearance_level
                FROM appenc.role_clearance
                WHERE role_name = %s;
            """, (role_name,))

            role_row = cur.fetchone()

            if role_row is None:
                raise ValueError("Unknown role.")

            role_clearance = role_row[0]


            # =================================================
            # Get field classification + authorization
            # =================================================

            cur.execute("""
                SELECT
                    classification_level,
                    allowed_roles
                FROM appenc.field_classification
                WHERE table_name = %s
                  AND column_name = %s;
            """, (
                table_name,
                column_name
            ))

            field_row = cur.fetchone()


            # If field is not explicitly classified,
            # treat it as UNCLASSIFIED.
            if field_row is None:
                required_level = "UNCLASSIFIED"
                allowed_roles = [role_name]

            else:
                required_level = field_row[0]
                allowed_roles = field_row[1]


            # =================================================
            # GATE 1: Security level
            # =================================================

            security_level_passed = (
                LEVELS[role_clearance]
                >=
                LEVELS[required_level]
            )


            # =================================================
            # GATE 2: Authorization / need-to-know
            # =================================================

            authorization_passed = (
                role_name in allowed_roles
            )


            # =================================================
            # GATE 3: Row permission
            # =================================================

            if role_name == "r_employee":

                row_passed = (
                    logged_in_emp_id
                    ==
                    target_emp_id
                )

            elif role_name in ["r_payroll", "r_hr"]:

                row_passed = True

            elif role_name == "r_analyst":

                row_passed = False

            else:

                row_passed = False


            # =================================================
            # FINAL DECISION
            # =================================================

            access_granted = (
                security_level_passed
                and
                authorization_passed
                and
                row_passed
            )


            return {

                "security_level": {
                    "passed": security_level_passed,
                    "role_clearance": role_clearance,
                    "required_level": required_level
                },

                "authorization": {
                    "passed": authorization_passed,
                    "role_name": role_name,
                    "allowed_roles": allowed_roles
                },

                "row_permission": {
                    "passed": row_passed,
                    "logged_in_emp_id": logged_in_emp_id,
                    "target_emp_id": target_emp_id
                },

                "access_granted": access_granted
            }

    finally:
        conn.close()