from client import stop_receive_thread


def test_stop_receive_thread(mocker):
    # Mock the receive_thread and stop_event
    mock_receive_thread = mocker.MagicMock()
    mock_stop_event = mocker.MagicMock()

    # Call the function
    stop_receive_thread(mock_receive_thread, mock_stop_event)

    # Check if stop_event.set() was called
    mock_stop_event.set.assert_called_once()

    # Check if receive_thread.join() was called
    mock_receive_thread.join.assert_called_once()
