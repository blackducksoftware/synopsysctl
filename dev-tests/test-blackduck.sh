echo "CREATE BLACK DUCK"
go test synopsysctl-tests/cmd_create/createBlackDuck_test.go -v -count=1 -run ".*"
echo ""

echo "START BLACK DUCK"
go test synopsysctl-tests/cmd_start/startBlackDuck_test.go -v -count=1 -run ".*"
echo ""

echo "STOP BLACK DUCK"
go test synopsysctl-tests/cmd_stop/stopBlackDuck_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE BLACK DUCK"
go test synopsysctl-tests/cmd_update/updateBlackDuck_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE BLACK DUCK UPGRADE"
go test synopsysctl-tests/cmd_update/updateBlackDuckUpgrade_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE BLACK DUCK MIGRATION"
go test synopsysctl-tests/cmd_update/updateBlackDuckMigration_test.go -v -count=1 -run ".*"
echo ""