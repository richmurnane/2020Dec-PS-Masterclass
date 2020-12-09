use role mask_admin_role;
use database poc_db;
use schema meta;
use warehouse rich_wh;

CREATE OR REPLACE PROCEDURE sp_apply_masking_policies(
  database_name varchar, 
  schema_name varchar, 
  table_name varchar)
RETURNS string
LANGUAGE javascript
EXECUTE AS owner
AS 
$$
try {
    var whereAmI = 1;
    var return_array = [];
    var counter = 0;
    var easyErrorMsg = "BEGIN";
    var database_name = DATABASE_NAME;
    var schema_name = SCHEMA_NAME;
    var table_name = TABLE_NAME;

    whereAmI = 2;
    var sqlquery = "SELECT column_name, logical_datatype, pii_npi_credit_open ";
    sqlquery = sqlquery + " FROM " + database_name + ".meta.metadata ";
    sqlquery = sqlquery + " WHERE database_name = '" + database_name + "' ";
    sqlquery = sqlquery + " AND   schema_name = '" + schema_name + "' ";
    sqlquery = sqlquery + " AND   table_name = '" + table_name + "' ";
    sqlquery = sqlquery + " AND   pii_npi_credit_open IS NOT NULL ";
    sqlquery = sqlquery + " AND   UPPER(pii_npi_credit_open) <> 'OPEN';"

    whereAmI = 3;
    var stmt = snowflake.createStatement( {sqlText: sqlquery} );
    var rs = stmt.execute();

    whereAmI = 4;
    // Loop through the results, processing one row at a time... 
    while (rs.next())  {
        whereAmI = 5;
        counter = counter + 1;
        var column_name = rs.getColumnValue(1);
        var logical_datatype = rs.getColumnValue(2);
        var pii_npi_credit_open = rs.getColumnValue(3);
        var tmp_sqlquery = "ALTER TABLE " + database_name + ".";
        tmp_sqlquery = tmp_sqlquery + schema_name + "." + table_name;
        tmp_sqlquery = tmp_sqlquery + " MODIFY COLUMN " + column_name;
        tmp_sqlquery = tmp_sqlquery + " SET MASKING POLICY " + database_name;
        tmp_sqlquery = tmp_sqlquery + ".meta." + pii_npi_credit_open;
        tmp_sqlquery = tmp_sqlquery + "_" + logical_datatype + "_mask;"

        snowflake.execute({sqlText: tmp_sqlquery});
        return_array.push("complete - column: " + column_name);
      }

  return_array.push("process complete");
  return return_array.toString();
}

catch (err) {
   return_array.push("error found: " + easyErrorMsg);
   return_array.push("whereAmI: " + whereAmI);
   return_array.push("err.code: " + err.code);
   return_array.push("err.state: " + err.state);
   return_array.push("err.message: " + err.message);
   return_array.push("err.stacktracetxt: " + err.stacktracetxt);
   return return_array.toString();
}

$$;

grant usage on procedure sp_apply_masking_policies(varchar, varchar, varchar) to role producer_role;
  