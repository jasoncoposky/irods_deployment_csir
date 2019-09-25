#define RODS_SERVER 1

#include <cstddef>

#include "irods_error.hpp"
#include "irods_ms_plugin.hpp"
#include "rsModAVUMetadata.hpp"

namespace {
    int msiproxy_user(
        msParam_t* _user_name,
        msParam_t* _prev_user_name,
        ruleExecInfo_t* _rei ) {
        if(_rei->rsComm->clientUser.authInfo.authFlag < LOCAL_PRIV_USER_AUTH) {
            return _rei->status = SYS_NO_API_PRIV;
        }

        char *user_name_str = parseMspForStr( _user_name );
        if( !user_name_str ) {
            return SYS_INVALID_INPUT_PARAM;
        }

        fillStrInMsParam(_prev_user_name,  _rei->rsComm->clientUser.userName);
        rstrcpy(_rei->rsComm->clientUser.userName, user_name_str, NAME_LEN);
        _rei->status = 0;
        return _rei->status;
    }
}

extern "C"
irods::ms_table_entry* plugin_factory() {
    irods::ms_table_entry* msvc = new irods::ms_table_entry(2);

    msvc->add_operation<
        msParam_t*,
        msParam_t*,
        ruleExecInfo_t*>("msiproxy_user",
                         std::function<int(
                             msParam_t*,
                             msParam_t*,
                             ruleExecInfo_t*)>(msiproxy_user));
    return msvc;
}

