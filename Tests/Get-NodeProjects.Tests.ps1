BeforeAll {
    . "$PSScriptRoot/../Private/Get-NodeProjects.ps1"
    $fixtureRoot = "$PSScriptRoot/Fixtures"
}

Describe 'Get-NodeProjects' {
    Context 'path with Node.js projects' {
        It 'finds one result per package.json' {
            (Get-NodeProjects -Path $fixtureRoot).Count | Should -BeGreaterOrEqual 3
        }
        It 'returns ProjectPath and PackageJsonPath' {
            $r = (Get-NodeProjects -Path $fixtureRoot)[0]
            $r.ProjectPath     | Should -Not -BeNullOrEmpty
            $r.PackageJsonPath | Should -Not -BeNullOrEmpty
        }
        It 'PackageJsonPath filename is package.json' {
            Get-NodeProjects -Path $fixtureRoot | ForEach-Object {
                [System.IO.Path]::GetFileName($_.PackageJsonPath) | Should -Be 'package.json'
            }
        }
        It 'excludes package.json inside node_modules' {
            $tmp = "$fixtureRoot/VulnerableNpmProject/node_modules/plain-crypto-js/package.json"
            '{"name":"plain-crypto-js"}' | Set-Content $tmp
            try {
                Get-NodeProjects -Path "$fixtureRoot/VulnerableNpmProject" | ForEach-Object {
                    $_.PackageJsonPath | Should -Not -Match 'node_modules'
                }
            } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
        }
    }
    Context 'test fixture paths are excluded by default' {
        BeforeAll {
            $tmpRoot = Join-Path $TestDrive 'scanner-project'
            # Real project — should be discovered
            $realProj = Join-Path $tmpRoot 'src\my-app'
            $null = New-Item -ItemType Directory -Path $realProj -Force
            '{"name":"my-app"}' | Set-Content (Join-Path $realProj 'package.json')
            # Fixture project — should be excluded by default
            $fixProj = Join-Path $tmpRoot 'Tests\Fixtures\VulnerableProject'
            $null = New-Item -ItemType Directory -Path $fixProj -Force
            '{"name":"vulnerable"}' | Set-Content (Join-Path $fixProj 'package.json')
        }
        It 'finds the real project' {
            (Get-NodeProjects -Path $tmpRoot).Count | Should -Be 1
        }
        It 'does not return projects under Tests\Fixtures' {
            Get-NodeProjects -Path $tmpRoot | ForEach-Object {
                $_.ProjectPath | Should -Not -Match 'Fixtures'
            }
        }
        It 'includes fixture projects when ExcludePattern is explicitly empty' {
            (Get-NodeProjects -Path $tmpRoot -ExcludePattern @()).Count | Should -Be 2
        }
    }

    Context 'nonexistent path' {
        It 'returns empty without throwing' {
            { Get-NodeProjects -Path 'C:\DoesNotExist\Fake' } | Should -Not -Throw
            Get-NodeProjects -Path 'C:\DoesNotExist\Fake' | Should -BeNullOrEmpty
        }
    }
}
