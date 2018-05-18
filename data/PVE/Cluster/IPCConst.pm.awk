BEGIN {
    print "package PVE::Cluster::IPCConst;"
    print "use strict; use warnings;"
    print
    print "use base 'Exporter';"
    print
    print "my %IPC_OPS;"
    print "BEGIN {"
    print "  %IPC_OPS = ("
}

/^#define CFS_IPC/ {
    print "    " $2, "=>", $3 ","
}

END {
    print "  );"
    print "}"
    print "use constant \\%IPC_OPS;"
    print "our @EXPORT = keys(%IPC_OPS);"
}
