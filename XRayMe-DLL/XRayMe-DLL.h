#pragma once
#ifndef WINDOWS_H
#define WINDOWS_H
#include <Windows.h>
#endif

#ifndef DLLEXPORT
#define DLLEXPORT __declspec(dllexport) 
#endif

#include "cPEFile.h"
#include "cXRay.h"