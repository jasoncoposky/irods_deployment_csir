
# Single point of truth for an error value
get_error_value(*err) { *err = "ERROR_VALUE" }

# The code to return for the rule engine plugin framework to look for additional PEPs to fire.
RULE_ENGINE_CONTINUE { 5000000 }

# Error code if input is incorrect
SYS_INVALID_INPUT_PARAM { -130000 }

# metadata attribute driving policy for user status
prevent_disabled_users_attribute { "irods::user::status" }

# possible user status values
user_status_enabled_value { "enabled" }
user_status_disabled_value { "disabled" }
user_status_none_value { "none" }

get_user_status(*user_name) {
    *attr   = prevent_disabled_users_attribute
    *status = user_status_none_value
    foreach(*row in SELECT META_USER_ATTR_VALUE WHERE USER_NAME = '*user_name' AND META_USER_ATTR_NAME = '*attr') {
        *status = *row.META_USER_ATTR_VALUE
    }

    *status
} # get_user_status

pep_api_auth_request_pre(*INST, *COMM, *REQ) {
    *user_name = *COMM.user_user_name

    *status = get_user_status(*user_name)
    if(user_status_disabled_value == *status) {
        failmsg(SYS_INVALID_INPUT_PARAM, "User [*user_name] status is disabled")
    }
    RULE_ENGINE_CONTINUE
} # pep_api_auth_request_pre

