module inventory.test/product

go 1.23

require inventory.test/dependency v0.0.0

require inventory.test/testdependency v0.0.0

replace inventory.test/dependency => ./localdep

replace inventory.test/testdependency => ./localtestdep
