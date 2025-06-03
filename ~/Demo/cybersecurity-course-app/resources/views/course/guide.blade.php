@extends('layouts.app')

@section('content')
<div class="bg-white rounded-lg shadow-lg p-8">
    <div class="mb-6">
        <a href="{{ route('course.index') }}" class="text-blue-600 hover:text-blue-800">← Back to Course Home</a>
    </div>
    
    <div class="prose prose-lg max-w-none">
        {!! $content !!}
    </div>
</div>
@endsection 