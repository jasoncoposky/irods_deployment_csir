
DEFAULT_RESOURCE_NAME { "dirisa_root" }

acSetRescSchemeForCreate {
    msiSetDefaultResc(DEFAULT_RESOURCE_NAME,"preferred");
}

acSetRescSchemeForRepl {
    msiSetDefaultResc(DEFAULT_RESOURCE_NAME,"preferred");
}

