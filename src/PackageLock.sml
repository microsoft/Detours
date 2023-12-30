Version: 5
Closures: {
	Root: {
		'C++': {
			Detours: { Version: '../src', Build: 'Build0', Tool: 'Tool0' }
		}
	}
	Build0: {
		Wren: {
			'mwasplund|Soup.Cpp': { Version: '0.12.0' }
		}
	}
	Tool0: {
		'C++': {
			'mwasplund|copy': { Version: '1.0.0' }
			'mwasplund|mkdir': { Version: '1.0.0' }
		}
	}
}