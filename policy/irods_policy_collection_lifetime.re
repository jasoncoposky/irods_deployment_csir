# iRODS Collection Lifetime Policy
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# This is a policy implementation which provides the identification and reporting of collections which
# have exceeded their lifetimes.  A collection may be tagged with a metadata attribute and value which
# identifies the lifetime of the collection in days.
#
# An additional policy may be called to generate a report which lists any collections which are in violation
# of their determined lifetime.
#
# Data objects which are placed into a collection with the lifetime metadata tag will also inherit metadata which
# states the lifetime and parent collection
#

# Single point of truth for an error value
get_error_value(*err) { *err = "ERROR_VALUE" }

# The code to return for the rule engine plugin framework to look for additional PEPs to fire.
RULE_ENGINE_CONTINUE { 5000000 }

# Error code if input is incorrect
SYS_INVALID_INPUT_PARAM { -130000 }

# admin privilege value
LOCAL_PRIV_USER_AUTH { 5 }

# metadata attribute driving the policy in units of days, fractions of a day are allowed: e.g. 0.01
get_lifetime_metadata_attribute(*attr) { *attr = "irods::collection::lifetime" }

# defined root collection to trigger policy - removes catalog load
# NOTE: assumption is made that the collection does NOT end in a /
#get_participating_collection_root(*root) { *root = "/dirisa.ac.za/projects/" }
get_participating_collection_root(*root) { *root = "/tempZone/projects" }

# defined violating root collection to trigger read/write prevention
# NOTE: assumption is made that the collection does NOT end in a /
#get_violating_collection_root(*root) { *root = "/dirisa.ac.za/violating_projects/" }
get_violating_collection_root(*root) { *root = "/tempZone/violating_projects" }

get_collection_lifetime(*collection, *lifetime) {
    get_error_value(*err_val)
    get_error_value(*lifetime)
    get_lifetime_metadata_attribute(*attr)

    foreach( *row in SELECT META_COLL_ATTR_VALUE WHERE META_COLL_ATTR_NAME = '*attr' AND COLL_NAME = '*collection') {
        *lifetime = *row.META_COLL_ATTR_VALUE
    }
} # get_collection_lifetime

collection_violates_lifetime_constraint(*coll_name, *lifetime, *violation_time) {
    get_error_value(*err_val)
    get_error_value(*create_time)
    *violation_time = 0

    foreach( *row in SELECT COLL_CREATE_TIME WHERE COLL_NAME = '*coll_name') {
        *create_time = *row.COLL_CREATE_TIME
    }

    if(*err_val == *create_time) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Failed to get COLL_CREATE_TIME for [*coll_name]")
    }

    if(*create_time != *err_val) {
        # 24hrs * 60 minutes * 60 seconds
        *seconds_per_day = 24.0 * 60.0 * 60.0

        *lifetime_days_dbl = double(*lifetime)

        msiGetSystemTime(*sys_time, '')
        *clean_sys_time = triml(*sys_time, "0")
        *cleaner_sys_time = triml(*clean_sys_time, " ")
        *sys_time_dbl = double(*cleaner_sys_time)
        *sys_time_days_dbl = *sys_time_dbl / *seconds_per_day

        *clean_create_time = triml(*create_time, "0")
        *cleaner_create_time = triml(*clean_create_time, " ")
        *create_time_dbl = double(*cleaner_create_time)
        *create_time_days_dbl = *create_time_dbl / *seconds_per_day

        *total_days_dbl = *create_time_days_dbl + *lifetime_days_dbl
        if(*sys_time_days_dbl > *total_days_dbl) {
            *violation_time = *sys_time_days_dbl - *total_days_dbl
        }
    }

} # collection_violates_lifetime_constraint

get_project_collection_from_path(*logical_path, *project_collection) {
    get_participating_collection_root(*root_coll)
    get_error_value(*project_collection)
    get_error_value(*parent)
    *full_path = *logical_path

    while(*parent != *root_coll && *parent != "/") {
        *ec = errormsg(msiSplitPath(*full_path, *parent, *child), *msg);
        if (*ec < 0) {
            failmsg(*ec, *msg);
        }

        if(*parent == *root_coll) {
            *project_collection = *parent ++ "/" ++ *child
        }
        else {
            *full_path = *parent
        }
    } # while

} # get_project_collection_from_path

# metadata inheritance
pep_api_data_obj_put_post(*INSTANCE_NAME, *COMM, *DATAOBJINP, *BBUFF, *PORTAL_OPR_OUT) {
    get_error_value(*err_val)
    *logical_path = *DATAOBJINP.obj_path
    get_participating_collection_root(*root_coll)

    if(*logical_path like *root_coll++"/*") {
        get_project_collection_from_path(*logical_path, *project_collection)
        get_collection_lifetime(*project_collection, *lifetime)
        if(*err_val != *lifetime) {
            # apply metadata to data object
            get_lifetime_metadata_attribute(*attr)
            msiset_avu("-d", *logical_path, *attr, *project_collection, *lifetime)
        }
    }
    RULE_ENGINE_CONTINUE
} # pep_api_data_obj_put_post

# prevent reads, writes, and moves to the violating project root
prevent_operation_on_violating_project_collection(*CTX) {
    *logical_path = *CTX.logical_path
    *user_auth_flag = *CTX.user_auth_info_auth_flag
    get_violating_collection_root(*root)

    *match = (*logical_path like *root++"/*")
    *priv = (int(*user_auth_flag) < LOCAL_PRIV_USER_AUTH)

    if(*match && *priv) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Unable to access violating project collections")
    }
}

pep_resource_open_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_open_pre

pep_resource_create_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_create_pre

pep_resource_unlink_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_unlink_pre

pep_resource_rename_pre(*INSTANCE, *CTX, *OUT, *FILENAME) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_rename_pre

