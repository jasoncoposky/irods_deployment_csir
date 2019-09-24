project_collection_creation

A script to create a project collection within /dirisa.ac.za/projects and annotat that collection with a metadata attribute / value pair which dictates the lifetime of the project collection

Options Include:
    *name - The name of the project collection
    *lifetime - The expected lifetime of the project in days

Interactive Usage:
    irods@avogadro:~$ irule -F project_collection_creation.r
    Default *name=
        New *name="project02"
    Default *lifetime=
        New *lifetime=0.01

Command Line Usage:
    irule -F project_collection_creation.r "*name='project03'" *lifetime=0.02



project_collection_violation_report

A script which will scan the project collection root for project collections which are in violation of their lifetime.  Violating collections make be then manually or automatically moved to the violationg project collection root: /dirisa.ac.za/violating_projects/

Command Line Usage:
    irule -F project_collection_violation_report.r

    Example Output:
    [/tempZone/projects/project01] in violation of lifetime constraint by [0.166806] days



