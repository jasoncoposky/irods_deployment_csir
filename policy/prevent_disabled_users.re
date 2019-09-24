
# Single point of truth for an error value
get_error_value(*err) { *err = "ERROR_VALUE" }

# The code to return for the rule engine plugin framework to look for additional PEPs to fire.
RULE_ENGINE_CONTINUE { 5000000 }

# Error code if input is incorrect
SYS_INVALID_INPUT_PARAM { -130000 }

# metadata attribute driving policy for user status
USER_STATUS_ATTRIBUTE { "irods::user::status" }

# possible user status values
USER_STATUS_VALUE_ENABLED { "enabled" }
USER_STATUS_VALUE_DISABLED { "disabled" }
USER_STATUS_VALUE_NONE { "none" }

get_user_status(*user_name) {
    *attr   = USER_STATUS_ATTRIBUTE
    *status = USER_STATUS_VALUE_NONE
    foreach(*row in SELECT META_USER_ATTR_VALUE WHERE USER_NAME = '*user_name' AND META_USER_ATTR_NAME = '*attr') {
        *status = *row.META_USER_ATTR_VALUE
    }

    *status
} # get_user_status

pep_api_auth_request_pre(*INST, *COMM, *REQ) {
    *user_name = *COMM.user_user_name

    *status = get_user_status(*user_name)
    if(USER_STATUS_VALUE_DISABLED == *status) {
        failmsg(SYS_INVALID_INPUT_PARAM, "User [*user_name] status is disabled")
    }
    RULE_ENGINE_CONTINUE
} # pep_api_auth_request_pre

