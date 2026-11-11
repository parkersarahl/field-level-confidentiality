DROP SCHEMA IF EXISTS appenc CASCADE;

CREATE SCHEMA appenc;


-- =========================================================
-- 1. Employee basic profile
-- =========================================================

CREATE TABLE appenc.employees (
    emp_id      INT PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    department  TEXT NOT NULL,
    title       TEXT NOT NULL,
    hire_date   DATE NOT NULL
);


-- =========================================================
-- 2. Role clearance
-- Must exist before app_users
-- =========================================================

CREATE TABLE appenc.role_clearance (
    role_name        TEXT PRIMARY KEY,
    clearance_level  TEXT NOT NULL
);


-- Initial role clearance policy

INSERT INTO appenc.role_clearance (
    role_name,
    clearance_level
)
VALUES
    ('r_employee', 'CONFIDENTIAL'),
    ('r_payroll',  'SECRET'),
    ('r_hr',       'CONFIDENTIAL'),
    ('r_analyst',  'UNCLASSIFIED');


-- =========================================================
-- 3. Application users / login information
-- =========================================================

CREATE TABLE appenc.app_users (
    user_id        TEXT PRIMARY KEY,

    password_hash  TEXT NOT NULL,

    role_name      TEXT NOT NULL
        REFERENCES appenc.role_clearance(role_name),

    emp_id         INT NOT NULL UNIQUE
        REFERENCES appenc.employees(emp_id)
        ON DELETE CASCADE
);


-- =========================================================
-- 4. Compensation
-- =========================================================

CREATE TABLE appenc.compensation (
    emp_id       INT PRIMARY KEY
                 REFERENCES appenc.employees(emp_id)
                 ON DELETE CASCADE,

    salary_enc   BYTEA NOT NULL,

    salary_band  TEXT NOT NULL,

    pay_freq     TEXT NOT NULL
);


-- =========================================================
-- 5. Tax and bank information
-- =========================================================

CREATE TABLE appenc.tax_bank (
    emp_id      INT PRIMARY KEY
                REFERENCES appenc.employees(emp_id)
                ON DELETE CASCADE,

    ssn_enc     BYTEA NOT NULL,

    ssn_last4   TEXT NOT NULL,

    bank_name   TEXT NOT NULL,

    acct_enc    BYTEA NOT NULL,

    acct_last4  TEXT NOT NULL
);


-- =========================================================
-- 6. Benefits
-- =========================================================

CREATE TABLE appenc.benefits (
    emp_id          INT PRIMARY KEY
                    REFERENCES appenc.employees(emp_id)
                    ON DELETE CASCADE,

    plan_name       TEXT NOT NULL,

    coverage_tier   TEXT NOT NULL,

    dependents_enc  BYTEA NOT NULL
);


-- =========================================================
-- 7. Field classification
-- =========================================================

CREATE TABLE appenc.field_classification (
    table_name            TEXT NOT NULL,

    column_name           TEXT NOT NULL,

    classification_level  TEXT NOT NULL,

    allowed_roles         TEXT[] NOT NULL,

    PRIMARY KEY (
        table_name,
        column_name
    )
);


-- =========================================================
-- 8. Initial field security policy
-- =========================================================

INSERT INTO appenc.field_classification (
    table_name,
    column_name,
    classification_level,
    allowed_roles
)
VALUES

    (
        'compensation',
        'salary_enc',
        'CONFIDENTIAL',
        ARRAY[
            'r_employee',
            'r_payroll',
            'r_hr'
        ]
    ),

    (
        'tax_bank',
        'ssn_enc',
        'SECRET',
        ARRAY[
            'r_payroll'
        ]
    ),

    (
        'tax_bank',
        'acct_enc',
        'SECRET',
        ARRAY[
            'r_payroll'
        ]
    ),

    (
        'benefits',
        'dependents_enc',
        'CONFIDENTIAL',
        ARRAY[
            'r_employee',
            'r_hr'
        ]
    );