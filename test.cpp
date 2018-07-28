#include <exception>
#include <stdexcept>

int main()
{
	try
	{
		throw std::runtime_error("test");
	}
	catch (const std::exception& e)
	{
	}

	try
	{
		throw std::runtime_error("test2");
	}
	catch (const std::exception& e)
	{
	}
}