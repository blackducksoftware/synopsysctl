echo "CREATE ALERT"
go test synopsysctl-tests/cmd_create/createAlert_test.go -v -count=1 -run ".*"
echo ""

echo "START ALERT"
go test synopsysctl-tests/cmd_start/startAlert_test.go -v -count=1 -run ".*"
echo ""

echo "STOP ALERT"
go test synopsysctl-tests/cmd_stop/stopAlert_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE ALERT"
go test synopsysctl-tests/cmd_update/updateAlert_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE ALERT UPGRADE"
go test synopsysctl-tests/cmd_update/updateAlertUpgrade_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE ALERT MIGRATION"
go test synopsysctl-tests/cmd_update/updateAlertMigration_test.go -v -count=1 -run ".*"
echo ""