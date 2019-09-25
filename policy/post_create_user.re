acPostProcForCreateUser {
    # user and home collection
    *home = "/"++$rodsZoneProxy++"/home/"++ $otherUserName

    # object and size quotas
    *count = "1000000" # number of objects
    *size  = "100000000000" # 100G in bytes

    # set logical quotas
    logical_quotas_init(*home, *count, *size)

    # implement email policy here
    # TODO
}


