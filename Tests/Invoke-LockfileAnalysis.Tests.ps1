BeforeAll {
    . "$PSScriptRoot/../Private/Invoke-LockfileAnalysis.ps1"
    $fix = "$PSScriptRoot/Fixtures"
}

Describe 'Invoke-LockfileAnalysis' {
    Context 'clean npm (axios@1.14.0)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/CleanProject" }
        It 'HasVulnerableAxios = false'      { $r.HasVulnerableAxios      | Should -BeFalse }
        It 'HasMaliciousPlainCrypto = false' { $r.HasMaliciousPlainCrypto | Should -BeFalse }
        It 'LockfileType = npm'              { $r.LockfileType            | Should -Be 'npm' }
        It 'no Error'                        { $r.Error                   | Should -BeNullOrEmpty }
    }
    Context 'vulnerable npm (axios@1.14.1)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerableNpmProject" }
        It 'HasVulnerableAxios = true'             { $r.HasVulnerableAxios      | Should -BeTrue }
        It 'VulnerableAxiosVersion = 1.14.1'       { $r.VulnerableAxiosVersion  | Should -Be '1.14.1' }
        It 'HasMaliciousPlainCrypto = true'        { $r.HasMaliciousPlainCrypto | Should -BeTrue }
    }
    Context 'vulnerable yarn (axios@0.30.4)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerableYarnProject" }
        It 'HasVulnerableAxios = true'       { $r.HasVulnerableAxios     | Should -BeTrue }
        It 'VulnerableAxiosVersion = 0.30.4' { $r.VulnerableAxiosVersion | Should -Be '0.30.4' }
        It 'HasMaliciousPlainCrypto = true'  { $r.HasMaliciousPlainCrypto | Should -BeTrue }
        It 'LockfileType = yarn'             { $r.LockfileType           | Should -Be 'yarn' }
    }
    Context 'vulnerable pnpm (axios@1.14.1)' {
        BeforeAll { $r = Invoke-LockfileAnalysis -ProjectPath "$fix/VulnerablePnpmProject" }
        It 'HasVulnerableAxios = true'      { $r.HasVulnerableAxios      | Should -BeTrue }
        It 'VulnerableAxiosVersion = 1.14.1' { $r.VulnerableAxiosVersion | Should -Be '1.14.1' }
        It 'HasMaliciousPlainCrypto = true' { $r.HasMaliciousPlainCrypto | Should -BeTrue }
        It 'LockfileType = pnpm'            { $r.LockfileType            | Should -Be 'pnpm' }
    }
    Context 'malformed JSON' {
        It 'does not throw'           { { Invoke-LockfileAnalysis -ProjectPath "$fix/MalformedProject" } | Should -Not -Throw }
        It 'returns an Error message' { (Invoke-LockfileAnalysis -ProjectPath "$fix/MalformedProject").Error | Should -Not -BeNullOrEmpty }
    }
    Context 'no lockfile' {
        It 'returns LockfileType null and HasVulnerableAxios false' {
            $r = Invoke-LockfileAnalysis -ProjectPath $TestDrive
            $r.LockfileType       | Should -BeNullOrEmpty
            $r.HasVulnerableAxios | Should -BeFalse
        }
    }
}
