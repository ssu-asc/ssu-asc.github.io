---
layout: page
title: tetris-almost-from-scratch
description:  This is an attempt of making the game Tetris using modern programming languages
tags: ["game", "tetris", "old-games", "javascript-games", "hackathon", "game-development"]
dropdown: Games
priority: 110
---
<!-- Automatically generated. Run search_repos.rb to rebuild -->


This is an attempt of making the game [Tetris](https://en.wikipedia.org/wiki/Tetris) using modern programming languages. The idea is to time the development and track the progress and the time it took to get in each stage in this document. If possible I want to finish this project in under 24 h.

Tetris is the first software to be exported from the USSR to the US and became and not only became one of the most famous computer games, it has been released for nearly every videogame console and computer operating system.

For this project, I'll be using the engine built for the [asteroids-almost-from-scratch](https://github.com/luxedo/asteroids-almost-from-scratch). I'll try to improve it and try to draw only characters on screen. The idea is to simulate the original game and also show an improved view using the same engine.

![original tetris](https://upload.wikimedia.org/wikipedia/en/7/7c/Tetris-VeryFirstVersion.png)

The game is based in html5/canvas, CSS and ES6 javascript.

#### Check it out [here](https://tetris-almost-from-scratch.firebaseapp.com/)

## Goals
*   ~~Add `LICENSE.md` and `README.md`~~
*   ~~Host somewhere~~
*   ~~Copy [TETRIS](https://luxedo.github.io/pong-almost-from-scratch/) project base~~
*   ~~Cleanup the old game~~
*   ~~Create the board~~
*   ~~Update drawing/writing functions~~
*   ~~Create the 'block' class~~
*   ~~Create "gravity" and game timing~~
*   ~~Tweak the user input mechanics~~
*   ~~Implement rotation mechanics~~
*   ~~Create collision mechanics~~
*   ~~Create line destruction mechanics~~
*   ~~Create levels/scoring~~
*   ~~Create game over mechanics and screen~~
*   ~~Create "next piece" display~~
*   ~~Create Menu screen and Credits screen~~
*   ~~Create high-scores~~
*   ~~Add sounds~~
*   ~~Fix playtesters requests~~
*   ~~Finished!~~

## Progress reports
00:00 - START! Well, now it's 6th of June 2017 and I'm a little drunk already.
I'm not going to work that much today but at least it's a beginning.

## 00:30 - Copied files from TETRIS project and hosted the page
Well, I'm quite slow today, but the foundations have been built. The game should
be available already using [gh-pages](https://pages.github.com/)

## 00:45 - Cleanup the old game
It was quite easy to cleanup the old game, now I have a clean canvas to start
working.

## 01:30 - Creating the board
#### Aaaaand two years later we're back
The idea to render the game, is to use fixed character positions and draw layers
of characters over this grid. The background layer should be the board and any
other data from sides of the board. I used a *mono spaced* font and intend to
use a [black square ■ from UTF-8](https://www.fileformat.info/info/unicode/char/25a0/index.htm) as the building blocks for the [tetrominoes](https://en.wikipedia.org/wiki/Tetromino).
One problem, is that using a regular space between the lines results in a weird
board shape:
![board regular spacing](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/board_regular_spacing.png)
The original developer, [Alexey Pajitnov](https://en.wikipedia.org/wiki/Alexey_Pajitnov),
solved this problem by using two characters for each block in the tetrominoes.
Since these **almost-from-scratch** projects always have a few twists, I will
compress the lines and draw the blocks with a single character.
![board compressed spacing](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/board_compressed_spacing.png)

## 03:45 - Update drawing/writing functions
First of all, I had to change the structure of the project because of some
annoying messages in my editor about variables out of scope. I renamed the files
to use them as modules and use the [`import` statement](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import).

![modules](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/modules.png)

Then, I proceeded to creating the drawing functions. First I wrote the data for
the tetrominoes. They're just some ■ characters in the correct position.

![tetrominoes](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/tetrominoes.png)

We also need to rotate the tetrominoes, I did not put much tought in for the
rotation for now. The final result looks like this:

![rotation](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/rotation.png)

## 04:00 - Create the 'block' class
With the drawing functions in place, it was quite easy to draw the blocks. We
don't have the collision mechanics nor the user input, that will change the
class quite a bit.

![moving](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/moving.gif)


## 04:20 - Create "gravity" and game timing
Gravity was quite simple to implement, just move the block down at a certain
interval. Then, this interval was added to a variable to set the level of
difficulty afterwards.

## 06:30 - Tweak the user input mechanics
First of all, I had to rewrite the gameloop. The old version was very confusing
and hard to tweak. Now it's simpler and I wrote using ES6 `class` notation. This
refactoring took quite some time.

![game class](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/game_class.png)

I have deleted the old user input, so we're going to make it again. I salvaged
some of the old code, but to summarize I made a class that listen for the `keyup`
and `keydown` events and stores the pressed buttons in an `object`. I also
implemented three handful methods:
-   `isDown` - Checks if the current key is pressed
-   `isActive` - Checks if the current may be triggered again. The key gets active again if the player releases it.
-   `isHolding` - Checks if the current key is being held for an specified time interval. This is useful to make the tetrominoes move when the player holds the key.

After this refactoring we can move the pieces!!

![input](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/input.gif)

## 7:00 - Implement rotation mechanics
Looking up in the interwebs, I found that the rotation mechanics has a name,
it's called [Super Rotation System](http://tetris.wikia.com/wiki/SRS) or **SRS**
for short.

![pieces rotation map](https://i.stack.imgur.com/JLRFu.png)

Fortunately, the simple rotation method that I implemented previously is exactly
the **SRS**, So I don't need to change it:

![srs](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/srs.gif)


## 11:40 - Create collision mechanics
Now we need to know when the pieces are touching the borders of the board.
There are two checks that needs to be done:
1. Check for collision with the walls and bottom.
2. Check for collision in spinning moves and
[Wall Kick](http://tetris.wikia.com/wiki/Wall_kick) the tetromino when
applicable.

There's a third check that could be made, the
[T Spin](http://tetris.wikia.com/wiki/T-Spin). Hopefully it will occur naturally.

To do this, each update fires a function to check for the sides of the pieces,
if the piece is going through a wall then it's kicked back or rotated back
(before the draw). If the bottommost side of the piece is below another piece or
wall, then it's kicked back and locked in place.

To do this it took quite some time. Sometimes the pieces would clip into each
other, or rotate apparently at random. But alas it's done. The main problems that
I had were to prioritize the actions to apply to the pieces according to user input.
Eg: if the user spins and the piece kicks off the wall, then by rotating it again
it wouldn't go back to it's previous position.

![collision](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/collision.gif)

## 12:10 - Create line destruction mechanics
And we're half way there! So far we have a playable demo, but the lines that are
full doesn't break.

The solution for this was to just filter the array that contains the placed
blocks for complete rows. Then I map over the array sliding down all pieces that
were above that line.

![break](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/break.gif)


## 13:00 - Create levels/scoring
The scoring system I used was the [Original Nintendo Scoring System](http://tetris.wikia.com/wiki/Scoring). In summary it is a table of a base according to the number of broken lines times the current level+1.

For the levels, I chose to increase it for every 10 broken lines, as in the NES
version.

To show the socores (`СЧЕТ`) and the level (`УРОВЕНЬ`) I decided to use the
original words in russian.

![score](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/score.gif)

## 15:30 - Create game over mechanics and screen
To check for a `Game Over` is quite simple with the `Block` class. I just have
to ask if there's any block above the screen. Then I had to create the screen
with some options after the game is over.

![Game Over](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/gameover.gif)

## 16:00 - Create "next piece" display
Finally an easy task again! For this display, we already had all the pieces in
hand. The `Block` class provided us with the tetromino draw and the screen
already had text in it, which I just edited.

![nextpiece](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/nextpiece.gif)

## 17:00 - Create Menu screen and Credits screen
For those screens I just had to copy the `Game Over` screen and edit a bit the
text for each one. I also created another parent class that is a screen with
the background and border for those screens to inherit.

![Menu and Credits](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/menu_credits.gif)

## 22:30 - Create high-scores
I implemented the `High Scores` for the [Asteroids](https://luxedo.github.io/asteroids-almost-from-scratch/) game and deployed on [Heroku](https://www.heroku.com/).
I'ts quite easy to work with them but unfortunately I'm out of [dynos](https://www.heroku.com/dynos).
Because of that I had to look for another host.

I chose to host at [Firebase](https://firebase.google.com) because their free tier
is quite nice. This game is not built for mobile but I intend to port it in the
future. It was also a chance to learn how to use the `Firebases`'s services and I
really enjoyed the experience. It took around 5 hours of studying and messing around
and 30 minutes of coding to make the `High Scores` work.

In the end, `Firebase` takes care of a lot of complexity when setting up a
database which is very nice. In the end, I just had to use their javascript
client to read and write in the database and hopefully the security part is
handled by them. I still don't understand how [Progressive Web Apps](https://developers.google.com/web/progressive-web-apps/)
are meant to be built, but I know that this app is working.

![High Score](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/high_score.png)

Because of the Firebase studies, I'm going to extend the project's deadline to
26 hours.

## 26:00 - Add sounds
Phew this took more time than I imagined. I just blew my newest deadline.

I had code from the previous games to play sounds, but I decided to
investigate whats new. I found out that the [Web Audio API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API)
is much better than the old `<audio>` tags that I used to use. I had
to learn how to use it, but it feels much better than the old method
that included a couple of `setTimeout`s.

I'm not sure if the original tetris had sounds or music. For nostalgia
sake, I included the game theme in the `Menu Screen`. I also added some
generic blip noises for other commands.

I made a class to hide the complexity of dealing with sounds:

![Sound](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/sound_class.png)

Then I just have to call the sounds whenever they're needed:

![Calling Sound](https://raw.githubusercontent.com/luxedo/tetris-almost-from-scratch/master//report-assets/calling_sound.png)


Thanks to [archive.org](https://archive.org) for the theme, `n_audioman`,
`LittleRobotSoundFactory` and `jeckkech` for the other sounds in [freesound.org](https://freesound.org)
and `David Whittaker` for the gameover sound at zxart.ee.",

Now, I'm releasing the game for the playtesters.

## 27:15 - Fix playtesters requests
I deployed the game and got the following feedback

-   ~~Confusing gap between pieces and side walls (Ule)~~
-   ~~Rotate piece with `ArrowUp` (Ule)~~
-   ~~Pause game with ESC (Ule)~~
-   ~~Tetrominoes have rectangular blocks (Me)~~
-   Game has frozen (Kaska)
-   ~~Menu cursor is out of place (Sofia)~~

## 27:20 - Finished
So I have finished this version of the game, unfortunately I blew the schedule
but only by a small portion, also I could not reproduce a bug that happened to
`Pedro`, whenever I have more information about it I'll fix it.

Thanks to the playtesters Ulisses Sato, Pedro Kersten, [Sofia "faifos" Faria](https://github.com/faifos).

Next up! Minesweeper? 🤔


## License

> This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
>
> This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
>
> You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.


