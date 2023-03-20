#include <iostream>
#include <Windows.h>
#include <LIEF/LIEF.hpp>
#include <fstream>

auto GetAllFilesWithinFolder(std::string Folder) -> std::vector<std::string>
{

	std::vector<std::string> DllNames;
	std::string searchPath = Folder + "/*.dll*";

	WIN32_FIND_DATAA FindData;

	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &FindData);

	if (hFind != INVALID_HANDLE_VALUE)
	{

		do
		{

			if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{

				DllNames.push_back(FindData.cFileName);

			}

		} while (FindNextFileA(hFind, &FindData));

	}

	return DllNames;
}

auto main() -> int
{

	std::string Folder = "C:\\Users\\vboxuser\\Desktop\\DLL\\";

	std::vector<std::string> DllNames = GetAllFilesWithinFolder(Folder);

	std::ofstream Stream;
	std::ostringstream aux;
	std::string Write;

	Stream.open(Folder + "arquivo.txt");

	for (auto i = 0; i < DllNames.size(); i++)
	{

		aux << DllNames[i] << std::endl;
		Write = aux.str();
		Stream << Write;

		std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(Folder + DllNames[i]);

		for (auto j = 0; j < pe->exported_functions().size(); j++)
		{

			std::cout << pe->exported_functions()[j].name() << std::endl;

			aux << pe->exported_functions()[j].name() << std::endl;
			Write = aux.str();

			Stream << Write;	
		}

	}

	Stream.close();

}