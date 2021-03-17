'use strict';

import { Component } from 'react';
import { render as ReactDomRender } from 'react-dom';

class App extends Component {

	constructor(props) {
		super(props);
		this.state = {};
	}

	render() {
		return (
			<h1>Hello React</h1>
		)
	}
}

ReactDomRender(
	<App />,
	document.getElementById('react')
)
