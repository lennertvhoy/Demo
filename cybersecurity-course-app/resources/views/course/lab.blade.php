@extends('layouts.app')

@section('content')
<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item"><a href="{{ route('course.index') }}">Home</a></li>
                    <li class="breadcrumb-item active">{{ $title }}</li>
                </ol>
            </nav>

            <div class="lab-content">
                {!! \Illuminate\Support\Str::markdown($content) !!}
            </div>

            <div class="mt-5">
                <a href="{{ url()->previous() }}" class="btn btn-secondary">← Back to Module</a>
            </div>
        </div>
    </div>
</div>

@push('styles')
<style>
    .lab-content {
        font-size: 1.1rem;
        line-height: 1.7;
    }
    .lab-content h1 {
        font-size: 2.5rem;
        margin-bottom: 2rem;
    }
    .lab-content h2 {
        font-size: 2rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .lab-content h3 {
        font-size: 1.5rem;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .lab-content pre {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.25rem;
        overflow-x: auto;
    }
    .lab-content code {
        background-color: #f8f9fa;
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-size: 0.9em;
    }
    .lab-content pre code {
        background-color: transparent;
        padding: 0;
    }
    .lab-content blockquote {
        border-left: 4px solid #dee2e6;
        padding-left: 1rem;
        margin: 1rem 0;
        color: #6c757d;
    }
</style>
@endpush
@endsection 