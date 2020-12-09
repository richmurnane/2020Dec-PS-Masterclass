--2020-Dec-PS-MClass-DDM.sql
--demo steps for masterclass POC/Demo 

-- create account objects (roles, users, database, and schemas)
    use role accountadmin;
        CREATE ROLE producer_role;
        CREATE ROLE consumer_role_01;
        CREATE ROLE consumer_role_02;
        CREATE ROLE consumer_role_03;
        CREATE ROLE consumer_role_04;
        CREATE ROLE consumer_role_05;
        CREATE ROLE consumer_role_06;
        CREATE ROLE allow_pii_role;
        CREATE ROLE allow_npi_role;
        CREATE ROLE allow_credit_role;
        --centralized management of masking
        CREATE ROLE mask_admin_role;  

    CREATE DATABASE poc_db;
    CREATE SCHEMA poc_db.meta;
    CREATE SCHEMA poc_db.autofin;

-- grants roles to users/roles & set ownership of database & schemas

    --run these
    use role accountadmin;
    GRANT ROLE producer_role    TO USER rich;
    GRANT ROLE consumer_role_01 TO USER rich;
    GRANT ROLE consumer_role_02 TO USER rich;
    GRANT ROLE consumer_role_03 TO USER rich;
    GRANT ROLE consumer_role_04 TO USER rich;
    GRANT ROLE consumer_role_05 TO USER rich;
    GRANT ROLE consumer_role_06 TO USER rich;
    GRANT ROLE mask_admin_role  TO USER rich;

    --visibility rules
    --show the visual for this
    --consumer_role_01 should not be able to access the table
    --consumer_role_02 should only see non-masked(open) columns in the table
    --consumer_role_03 should only see non-masked(open) + pii columns
    --consumer_role_04 should only see non-masked(open) + npi columns
    --consumer_role_05 should only see non-masked(open) + credit columns
    --consumer_role_06 should only see all columns
    GRANT ROLE allow_pii_role TO ROLE consumer_role_03;
    GRANT ROLE allow_npi_role TO ROLE consumer_role_04;
    GRANT ROLE allow_credit_role TO ROLE consumer_role_05;
    GRANT ROLE allow_pii_role TO ROLE consumer_role_06;
    GRANT ROLE allow_npi_role TO ROLE consumer_role_06;
    GRANT ROLE allow_credit_role TO ROLE consumer_role_06;

    --centralized management of masking
    --https://docs.snowflake.com/en/user-guide/security-column-intro.html#masking-policy-privileges

    --run this one
    GRANT apply masking policy ON account TO role mask_admin_role;  

    GRANT usage on WAREHOUSE rich_wh TO ROLE producer_role;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_01;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_02;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_03;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_04;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_05;
    GRANT usage on WAREHOUSE rich_wh TO ROLE consumer_role_06;
    GRANT usage on WAREHOUSE rich_wh TO ROLE mask_admin_role;

    grant ownership on schema poc_db.meta to role producer_role;
    grant ownership on schema poc_db.autofin to role producer_role;
    grant ownership on database poc_db to role producer_role;

    use role producer_role;
    GRANT USAGE ON DATABASE poc_db TO ROLE producer_role;
    GRANT USAGE ON DATABASE poc_db TO ROLE mask_admin_role;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_01;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_02;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_03;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_04;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_05;
    GRANT USAGE ON DATABASE poc_db TO ROLE consumer_role_06;

    GRANT USAGE ON schema poc_db.autofin TO ROLE producer_role;
    GRANT USAGE ON schema poc_db.autofin TO ROLE mask_admin_role;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_01;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_02;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_03;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_04;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_05;
    GRANT USAGE ON schema poc_db.autofin TO ROLE consumer_role_06;

    GRANT USAGE ON schema poc_db.meta TO ROLE mask_admin_role;

    GRANT create table on schema poc_db.meta TO ROLE mask_admin_role;
    GRANT create procedure on schema poc_db.meta TO ROLE mask_admin_role;
    GRANT create masking policy on schema poc_db.meta TO ROLE mask_admin_role;

-- create masking policies
    --opportunity for automating this
    --additional datatypes/etc.
    --pii
        use role mask_admin_role;
        use database poc_db;
        use schema meta;

        create or replace masking policy poc_db.meta.pii_str_mask as (val string) 
        returns string ->
            case
                when is_role_in_session('ALLOW_PII_ROLE') then val
                else '*********'
            end;

        create or replace masking policy poc_db.meta.pii_dt_mask as (val date) 
        returns date ->
            case
                when is_role_in_session('ALLOW_PII_ROLE') then val
                else '9999-12-31'::date
            end;

        create or replace masking policy poc_db.meta.pii_ts_mask as (val timestamp) 
        returns timestamp ->
            case
                when is_role_in_session('ALLOW_PII_ROLE') then val
                else '9999-12-31'::timestamp
            end;

        create or replace masking policy poc_db.meta.pii_int_mask as (val integer) 
        returns integer ->
            case
                when is_role_in_session('ALLOW_PII_ROLE') then val
                else -99999999999999999999999999999999999999
            end;

        create or replace masking policy poc_db.meta.pii_dec_mask as (val number) 
        returns number ->
            case
                when is_role_in_session('ALLOW_PII_ROLE') then val
                else -99999999999999999999999999999999999999::number(38,0)
            end;
    --npi
        create or replace masking policy poc_db.meta.npi_str_mask as (val string) 
        returns string ->
            case
                when is_role_in_session('ALLOW_NPI_ROLE') then val
                else '*********'
            end;

        create or replace masking policy poc_db.meta.npi_dt_mask as (val date) 
        returns date ->
            case
                when is_role_in_session('ALLOW_NPI_ROLE') then val
                else '9999-12-31'::date
            end;

        create or replace masking policy poc_db.meta.npi_ts_mask as (val timestamp) 
        returns timestamp ->
            case
                when is_role_in_session('ALLOW_NPI_ROLE') then val
                else '9999-12-31'::timestamp
            end;

        create or replace masking policy poc_db.meta.npi_int_mask as (val integer) 
        returns integer ->
            case
                when is_role_in_session('ALLOW_NPI_ROLE') then val
                else -99999999999999999999999999999999999999
            end;

        create or replace masking policy poc_db.meta.npi_dec_mask as (val number) 
        returns number ->
            case
                when is_role_in_session('ALLOW_NPI_ROLE') then val
                else -99999999999999999999999999999999999999::number(38,0)
            end;

    --credit
        create or replace masking policy poc_db.meta.credit_str_mask as (val string) 
        returns string ->
            case
                when is_role_in_session('ALLOW_CREDIT_ROLE') then val
                else '*********'
            end;

        create or replace masking policy poc_db.meta.credit_dt_mask as (val date) 
        returns date ->
            case
                when is_role_in_session('ALLOW_CREDIT_ROLE') then val
                else '9999-12-31'::date
            end;

        create or replace masking policy poc_db.meta.credit_ts_mask as (val timestamp) 
        returns timestamp ->
            case
                when is_role_in_session('ALLOW_CREDIT_ROLE') then val
                else '9999-12-31'::timestamp
            end;

        create or replace masking policy poc_db.meta.credit_int_mask as (val integer) 
        returns integer ->
            case
                when is_role_in_session('ALLOW_CREDIT_ROLE') then val
                else -99999999999999999999999999999999999999
            end;

        create or replace masking policy poc_db.meta.credit_dec_mask as (val number) 
        returns number ->
            case
                when is_role_in_session('ALLOW_CREDIT_ROLE') then val
                else -99999999999999999999999999999999999999::number(38,0)
            end;

-- create table with fake CUSTOMER data 
    use role producer_role;
    CREATE TABLE poc_db.autofin.customer (
        account_id    number(38,0),
        create_dt     timestamp_ltz,
        address       VARCHAR(250),
        credit_score  integer,
        ssn           VARCHAR(20),
        first_name    VARCHAR(100),
        last_name     VARCHAR(100),
        guid          VARCHAR(100));

    INSERT INTO poc_db.autofin.customer VALUES 
        (1, dateadd(minute, -5, current_timestamp()), 
            '450 Concar Dr, San Mateo, CA 94402', 
            1000,'012345678','Joe','Smith','4bd0b93a-cb6d-4eb2-b370-88f1131d6fa8'),
        (2, dateadd(days, -71, current_timestamp()), 
            '100 Main Street, Springfield, anyState 01234', 
            600,'123456789','Mary','Johnson','4ec6434f-4d2b-4f5a-b5ad-47969cf2893d'),
        (3, current_timestamp(), 
            '99 Park Avenue, New York, NY 10001', 
            12000,'101010101','Matthew','Jones','afe861d1-d9bf-4596-bd6c-2511feaa74f6'),
        (4, dateadd(years, -1, current_timestamp()), 
            '1600 Pennsylvania Avenue NW, Washington, DC 20500', 
            700,'111111111','George','Washington','d77ea0c5-d6e0-49cb-8bdc-3b560e2a4714');

    GRANT SELECT on poc_db.autofin.customer TO ROLE consumer_role_02;
    GRANT SELECT on poc_db.autofin.customer TO ROLE consumer_role_03;
    GRANT SELECT on poc_db.autofin.customer TO ROLE consumer_role_04;
    GRANT SELECT on poc_db.autofin.customer TO ROLE consumer_role_05;
    GRANT SELECT on poc_db.autofin.customer TO ROLE consumer_role_06;

-- apply masking policies manually, or via stored procedure 
    -- manually - using the mask_admin_role
        use role mask_admin_role;
        ALTER TABLE poc_db.autofin.customer MODIFY COLUMN address SET MASKING POLICY poc_db.meta.npi_str_mask;
        ALTER TABLE poc_db.autofin.customer MODIFY COLUMN credit_score SET MASKING POLICY poc_db.meta.credit_int_mask;
        ALTER TABLE poc_db.autofin.customer MODIFY COLUMN ssn SET MASKING POLICY poc_db.meta.pii_str_mask;
        ALTER TABLE poc_db.autofin.customer MODIFY COLUMN first_name SET MASKING POLICY poc_db.meta.npi_str_mask;
        ALTER TABLE poc_db.autofin.customer MODIFY COLUMN last_name SET MASKING POLICY poc_db.meta.npi_str_mask;

    -- stored procedure
        -- create and populate the metadata registration table 
            -- call it metadata, KISS
            -- cols: database,schema,table_name,column_name,pii_npi_credit_open,logical_datatype
            -- logical_datatype: STRING, INTEGER, DECIMAL, DATE, TIMESTAMP
            use role mask_admin_role;
            use warehouse rich_wh;
            use database poc_db;
            use schema meta;
            CREATE TABLE poc_db.meta.metadata (
                database_name          VARCHAR(50),
                schema_name            VARCHAR(50),
                table_name             VARCHAR(50),
                column_name            VARCHAR(50),
                logical_datatype       VARCHAR(20),
                pii_npi_credit_open    VARCHAR(6));

            INSERT INTO poc_db.meta.metadata VALUES 
                ('POC_DB','AUTOFIN','CUSTOMER','ACCOUNT_ID','DEC','OPEN'),
                ('POC_DB','AUTOFIN','CUSTOMER','CREATE_DT','TS','OPEN'),
                ('POC_DB','AUTOFIN','CUSTOMER','ADDRESS','STR','NPI'),
                ('POC_DB','AUTOFIN','CUSTOMER','CREDIT_SCORE','INT','CREDIT'),
                ('POC_DB','AUTOFIN','CUSTOMER','SSN','STR','PII'),
                ('POC_DB','AUTOFIN','CUSTOMER','FIRST_NAME','STR','NPI'),
                ('POC_DB','AUTOFIN','CUSTOMER','LAST_NAME','STR','NPI'),
                ('POC_DB','AUTOFIN','CUSTOMER','GUID','STR','OPEN');

        -- create and call the stored procedure to apply masking policies (no views)
            deploy the stored procedure - review sp_apply_masking_policies.sql
            use role producer_role;
            CALL poc_db.meta.sp_apply_masking_policies('POC_DB','AUTOFIN','CUSTOMER');

-- run test queries from various users/roles
    --visibility rules
    --consumer_role_01 should not be able to access the table
    --consumer_role_02 should only see non-masked(open) columns in the table
    --consumer_role_03 should only see non-masked(open) + pii columns
    --consumer_role_04 should only see non-masked(open) + npi columns
    --consumer_role_05 should only see non-masked(open) + credit columns
    --consumer_role_06 should only see all columns
    queries per role
        use role consumer_role_01;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;

        use role consumer_role_02;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;

        use role consumer_role_03;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;

        use role consumer_role_04;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;

        use role consumer_role_05;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;

        use role consumer_role_06;
        select * from poc_db.autofin.customer;
        select * from poc_db.autofin.customer where ssn = '012345678';
        select count(distinct ssn), min(ssn) min_ssn, max(ssn) max_ssn 
        from poc_db.autofin.customer;



-- run commands to show policies in account and on tables, etc.
    use role mask_admin_role;
    select * 
    from table(information_schema.policy_references(policy_name=>'POC_DB.META.PII_STR_MASK'));

-- q&a 

