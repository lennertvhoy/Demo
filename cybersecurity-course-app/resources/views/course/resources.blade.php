@extends('layouts.app')

@section('content')
<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <h1 class="display-4 mb-4">Additional Resources</h1>
            
            <div class="card mb-4">
                <div class="card-body">
                    <h2 class="h4 mb-3">📚 Recommended Books</h2>
                    <ul class="list-unstyled">
                        <li class="mb-2">• "The Web Application Hacker's Handbook" by Dafydd Stuttard</li>
                        <li class="mb-2">• "Applied Cryptography" by Bruce Schneier</li>
                        <li class="mb-2">• "Network Security Essentials" by William Stallings</li>
                        <li class="mb-2">• "The Art of Deception" by Kevin Mitnick</li>
                        <li class="mb-2">• "Security Engineering" by Ross Anderson</li>
                    </ul>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-body">
                    <h2 class="h4 mb-3">🛠️ Essential Tools</h2>
                    <div class="row">
                        <div class="col-md-6">
                            <h5>Network Security</h5>
                            <ul class="list-unstyled">
                                <li>• Wireshark - Network protocol analyzer</li>
                                <li>• Nmap - Network scanner</li>
                                <li>• Metasploit - Penetration testing framework</li>
                                <li>• pfSense - Firewall/router</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h5>Web Security</h5>
                            <ul class="list-unstyled">
                                <li>• Burp Suite - Web vulnerability scanner</li>
                                <li>• OWASP ZAP - Security testing tool</li>
                                <li>• SQLMap - SQL injection tool</li>
                                <li>• Nikto - Web server scanner</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-body">
                    <h2 class="h4 mb-3">🌐 Online Resources</h2>
                    <ul class="list-unstyled">
                        <li class="mb-2">• <strong>OWASP</strong> - Open Web Application Security Project</li>
                        <li class="mb-2">• <strong>SANS Institute</strong> - Security training and certification</li>
                        <li class="mb-2">• <strong>Cybrary</strong> - Free cybersecurity training</li>
                        <li class="mb-2">• <strong>HackTheBox</strong> - Penetration testing labs</li>
                        <li class="mb-2">• <strong>TryHackMe</strong> - Interactive cyber security training</li>
                    </ul>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-body">
                    <h2 class="h4 mb-3">🎓 Certifications to Consider</h2>
                    <div class="row">
                        <div class="col-md-6">
                            <h5>Entry Level</h5>
                            <ul class="list-unstyled">
                                <li>• CompTIA Security+</li>
                                <li>• CompTIA Network+</li>
                                <li>• CompTIA CySA+</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h5>Advanced</h5>
                            <ul class="list-unstyled">
                                <li>• CISSP - Certified Information Systems Security Professional</li>
                                <li>• CEH - Certified Ethical Hacker</li>
                                <li>• OSCP - Offensive Security Certified Professional</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-body">
                    <h2 class="h4 mb-3">💡 Practice Platforms</h2>
                    <ul class="list-unstyled">
                        <li class="mb-2">• <strong>PentesterLab</strong> - Learn web penetration testing</li>
                        <li class="mb-2">• <strong>VulnHub</strong> - Vulnerable VMs for practice</li>
                        <li class="mb-2">• <strong>OverTheWire</strong> - Wargames and challenges</li>
                        <li class="mb-2">• <strong>Root Me</strong> - Hacking challenges</li>
                        <li class="mb-2">• <strong>Hack This Site</strong> - Legal free training ground</li>
                    </ul>
                </div>
            </div>

            <div class="mt-5 text-center">
                <a href="{{ route('course.index') }}" class="btn btn-secondary">Back to Home</a>
            </div>
        </div>
    </div>
</div>
@endsection 