@extends('layouts.app')

@section('content')
<div class="bg-white rounded-lg shadow-lg p-8">
    <div class="mb-6">
        <a href="{{ route('course.index') }}" class="text-blue-600 hover:text-blue-800">← Back to Course Home</a>
    </div>
    
    <div class="prose prose-lg max-w-none">
        {!! $content !!}
    </div>
    
    <!-- Module Navigation -->
    <div class="mt-12 border-t pt-8">
        <div class="flex justify-between items-center">
            @php
                $modules = [
                    '1-fundamentals' => 'Module 1: Fundamentals',
                    '2-network-security' => 'Module 2: Network Security', 
                    '3-web-security' => 'Module 3: Web Security',
                    '4-cryptography' => 'Module 4: Cryptography',
                    '5-ethical-hacking' => 'Module 5: Ethical Hacking'
                ];
                $keys = array_keys($modules);
                $currentIndex = array_search($module, $keys);
            @endphp
            
            @if($currentIndex > 0)
                <a href="{{ route('course.module', $keys[$currentIndex - 1]) }}" class="flex items-center text-blue-600 hover:text-blue-800">
                    <span class="mr-2">←</span> Previous Module
                </a>
            @else
                <div></div>
            @endif
            
            @if($currentIndex < count($keys) - 1)
                <a href="{{ route('course.module', $keys[$currentIndex + 1]) }}" class="flex items-center text-blue-600 hover:text-blue-800">
                    Next Module <span class="ml-2">→</span>
                </a>
            @else
                <a href="{{ route('course.lab', 'lab-1-network-recon') }}" class="flex items-center text-green-600 hover:text-green-800">
                    Continue to Labs <span class="ml-2">→</span>
                </a>
            @endif
        </div>
    </div>
</div>
@endsection 