$ErrorActionPreference = "Stop"

$junit = Join-Path $PSScriptRoot "lib\junit-4.13.2.jar"
$hamcrest = Join-Path $PSScriptRoot "lib\hamcrest-core-1.3.jar"
$cp = "$junit;$hamcrest"

$mainSrc = Join-Path $PSScriptRoot "src\main\java"
$testSrc = Join-Path $PSScriptRoot "src\test\java"

$out = Join-Path $PSScriptRoot "out\test-classes"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Path $out | Out-Null

Write-Host "Compiling..."
javac -encoding UTF-8 -cp $cp -d $out `
  "$mainSrc\ArrayList.java" "$mainSrc\Car.java" "$mainSrc\CarList.java" `
  "$mainSrc\javaCarList.java" "$mainSrc\javaCar.java" `
  "$testSrc\ArrayListTest.java" "$testSrc\CarListTest.java" "$testSrc\JavaCarListTest.java"

Write-Host "Running tests..."
java -cp "$out;$cp" org.junit.runner.JUnitCore ArrayListTest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
java -cp "$out;$cp" org.junit.runner.JUnitCore CarListTest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
java -cp "$out;$cp" org.junit.runner.JUnitCore JavaCarListTest
