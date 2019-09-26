#
# Policy which will limit access to the modification of administrative
# metadata to only rodsadmin users
#
# NOTE: This policy assumes that irods_policy_logical_quotas, prevent_disabled_users
#       and project_collection_lifetime in order to reference the appropriate attributes

# The code to return for the rule engine plugin framework to look for additional PEPs to fire.
RULE_ENGINE_CONTINUE { 5000000 }

# Error code if input is incorrect
SYS_INVALID_INPUT_PARAM { -130000 }

# admin privilege value
LOCAL_PRIV_USER_AUTH { 5 }

administrative_metadata_list {
    list(
        logical_quotas_maximum_object_count_key()
        , logical_quotas_maximum_data_size_in_bytes_key()
        , logical_quotas_current_object_count_key()
        , logical_quotas_current_data_size_in_bytes_key()
        , project_collection_lifetime_attribute()
        , prevent_disabled_users_attribute()
    )
} # administrative_metadata_list

pep_api_mod_avu_metadata_pre(*INST, *COMM, *INP) {
    #writeLine("serverLog", "*INP")
    *user_auth_flag = *COMM.user_auth_info_auth_flag
    *user_not_rodsadmin = (int(*user_auth_flag) < LOCAL_PRIV_USER_AUTH)

    *opr  = *INP.arg0
    *attr = *INP.arg3

    *opr_is_mod = ( *opr == "set" || *opr == "add" || *opr == "rm" )
    if(*user_not_rodsadmin && *opr_is_mod) {
        *attrs_list = administrative_metadata_list()
        while(size(*attrs_list) > 0) {
            # pull head of list
            *val = str(hd(*attrs_list))

            # subset remainder of list
            *attrs_list = tl(*attrs_list)

            # chomp space
            *val = triml(*val, ' ')
            *val = trimr(*val, ' ')

            if(*attr == *val) {
                failmsg(
                    SYS_INVALID_INPUT_PARAM,
                    "User cannot modify administrative metadata")
            }
        } # while
    } # user is not rodsadmin

    RULE_ENGINE_CONTINUE

} # pep_api_mod_avu_metadata_pre


