module example.com/fvchurnprod

go 1.23

require (
	example.com/dep v1.0.0
	example.com/depfv v0.0.0
	example.com/dep2 v0.0.0
)

replace example.com/dep => ../dep

replace example.com/depfv => ../depfv

replace example.com/dep2 => ../dep2
