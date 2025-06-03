<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use League\CommonMark\CommonMarkConverter;
use League\CommonMark\Extension\Table\TableExtension;
use League\CommonMark\Extension\TaskList\TaskListExtension;
use League\CommonMark\Extension\Autolink\AutolinkExtension;
use League\CommonMark\Environment\Environment;

class CourseController extends Controller
{
    private $converter;
    
    public function __construct()
    {
        $this->converter = new CommonMarkConverter();
    }
    
    public function index()
    {
        // Return a simple JSON response for now to test if routes work
        return response()->json([
            'message' => 'CourseController index method called', 
            'timestamp' => now(),
            'status' => 'Routes are working!'
        ]);
    }
    
    public function module($module)
    {
        return response()->json([
            'message' => 'Module method called',
            'module' => $module,
            'timestamp' => now()
        ]);
    }
    
    public function lab($lab)
    {
        return response()->json([
            'message' => 'Lab method called',
            'lab' => $lab,
            'timestamp' => now()
        ]);
    }
    
    public function resources()
    {
        return response()->json([
            'message' => 'Resources method called',
            'timestamp' => now()
        ]);
    }
    
    public function courseGuide()
    {
        return response()->json([
            'message' => 'Course guide method called',
            'timestamp' => now()
        ]);
    }
} 