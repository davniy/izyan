module example.com/libasserthttpprod

go 1.23

require (
	example.com/dep v1.0.0
	example.com/libassertprod v0.0.0
)

replace example.com/dep => ../dep

replace example.com/libassertprod => ../libassertprod
